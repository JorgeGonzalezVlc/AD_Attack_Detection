# Credentials in Shares (Credenciales expuestas, recursos compartidos de red)

## Resumen del ataque

Las credenciales expuestas en recursos compartidos (CIFS/SMB) son probablemente el fallo en configuracion más común en entornos Active Directory. 

El atacante descubre fácilmente archivos con credenciales hardcodeadas en scripts, configuraciones y documentos compartidos accesibles.

Se trata de un escenario muy realista ya que en produccion en muchas ocasiones se pueden encontrar archivos con informacion privilegiada en su interior:
- Scripts PowerShell/Batch con contraseñas en texto plano
- Archivos `.config` y `.ini` con credenciales de bases de datos
- Documentos de configuración viejos sin protección
- Comandos `net use /user:DOMAIN\USER PASSWORD` en scripts de sincronización

Esto tiene in impacto crítico debido a que podemos encontrar credenciales que podrian pertenecer a:
- Cuentas de servicio (con permisos sobre aplicaciones críticas)
- Administradores del dominio
- Cuentas técnicas de terceros

## Objetivo del ataque

Quiero plasmar la emtodologia que deberia seguir siendo un usuario normal del dominio para:
1. Descubrir compartidas SMB accesibles
2. Buscar y extraer credenciales de archivos dentro
3. Usar esas credenciales para acceder a recursos protegidos

## Escenario del lab

```
Dominio:         adlab.local
Compartida:      \\DC01\scripts
Acceso:          "Todos" (Everyone)
Atacante:        pedri (usuario de dominio normal)
Objetivo:        Extraer credenciales de archivos de configuración
Método:          Enumeración + búsqueda con findstr
Evidencia:       Event ID 5145 (Detailed File Share)
```

## Paso 1: Configurar la vulnerabilidad

### 1.1 Crear la compartida SMB en DC01

En DC01, creo la carpeta `C:\Scripts` y la comparto:

```powershell
# Crear carpeta
New-Item -ItemType Directory -Path "C:\Scripts" -Force

# Crear compartida (GUI o PowerShell)
New-SmbShare -Name "scripts" -Path "C:\Scripts" -FullAccess "Todos" -Description "Script repository"
```

![Uso compartido avanzado de la carpeta Scripts, con permiso de lectura para Todos](<img/Creamos carpeta compartida.png>)

### 1.2 Crear archivos con credenciales

Dentro de `C:\Scripts`, creo los siguientes archivos que me resviran de prueba:

**Archivo 1: `config.ini`**
```ini
[Database]
Server=SQLSERVER01
Username=svc_sql
Password=P@ssw0rd123!
Database=ProductionDB
```

**Archivo 2: `backup.ps1`**
```powershell
# Script de backup automático
$username = "adlab\Administrator"
$password = "P@ssAdmin123!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

Copy-Item -Path "\\DC01\SYSVOL" -Destination "\\SERVER01\backups\sysvol_backup" -Credential $credential -Recurse
Write-Host "Backup completado"
```

**Archivo 3: `webserver.config`**
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="DBConnection" value="Server=SQLSERVER;uid=iis_service;pwd=IISSecure@2024" />
    <add key="SMTPPassword" value="MailAlert123!" />
  </appSettings>
</configuration>
```

**Archivo 4: `sync.bat`**
```batch
@echo off
echo Sincronizando archivos...
net use Z: \\FILESERVER\corporate /user:adlab\svc_backup SecureBackup@123 /persistent:yes
xcopy C:\data\* Z:\ /Y /S
echo Sincronización completada
```

![Los cuatro archivos con credenciales hardcodeadas ya dentro de C:\Scripts: backup, config, sync y webserver.config](<img/Creamos diferentes scripts simulando entorno.png>)

## Paso 2: Ejecutar el ataque

### 2.1 Descubrir compartidas accesibles

Desde JORGE-CLIENTE como `pedri`:

```powershell
# Ver compartidas del DC01
net view \\DC01

# Resultado esperado:
# \\DC01\scripts          - accesible
# \\DC01\SYSVOL          - accesible
# \\DC01\NETLOGON        - accesible
```

![net view \\DC01 desde pedri, mostrando las compartidas NETLOGON, Scripts y SYSVOL](<img/Vemos cuales son las carpetas compartidas.png>)

### 2.2 Acceder a la compartida

```powershell
# Acceder a la compartida
cd \\DC01\scripts
dir

# Listar archivos sospechosos (con configuraciones/scripts)
# Deberías ver: backup.ps1, config.ini, webserver.config, sync.bat
```

![Accediendo a \\DC01\Scripts desde JORGE-CLIENTE y viendo los cuatro archivos](<img/Desde la cuenta cliente vemos los archivos compartidos.png>)

### 2.3 Buscar credenciales con findstr (Living off the Land)

Busco credenciales con `findstr`. 
Se trata de una herramienta nativa de Windows y no genera alertas de "herramienta sospechosa" instalada. 
Buscaredmos cadenas de strings como `pass`, `pwd`...

```powershell
# Buscar archivos con "pass"
findstr /m /s /i "pass" *.ini
findstr /m /s /i "pass" *.config
findstr /m /s /i "pass" *.ps1
findstr /m /s /i "pass" *.bat

# Buscar archivos con "pw"
findstr /m /s /i "pw" *.config

# Buscar por nombre del dominio (ej: referencias a adlab\)
findstr /m /s /i "adlab" *.ps1
findstr /m /s /i "adlab" *.bat

# Ver el contenido exacto (sin /m, muestra líneas)
findstr /s /i "password" *.ini
findstr /s /i "pwd" *.config
findstr /s /i "adlab" *.ps1
```

![Primera pasada de findstr contra *.ini y *.config desde pedri](<img/Captura de pantalla 2026-07-09 202126.png>)

![findstr /m /s /i "pass" contra los archivos de \\DC01\Scripts, encontrando coincidencias en webserver.config y config.ini](<img/Captura de pantalla 2026-07-09 202406.png>)

### 2.4 Extraer credenciales encontradas

Credenciales descubiertas:

```
[config.ini]
Username: svc_sql
Password: P@ssw0rd123!

[backup.ps1]
Username: adlab\Administrator        ← DOMAIN ADMIN
Password: P@ssAdmin123!              ← CRÍTICA

[webserver.config]
Username: iis_service
Password: IISSecure@2024

[sync.bat]
Username: adlab\svc_backup
Password: SecureBackup@123
```

![Leyendo el contenido de backup.ps1, config.ini y sync.bat para extraer las credenciales en claro](<img/Enumeramos los diferentes archivos en busca de credenciales.png>)

### 2.5 Validar las credenciales (opcional)

```powershell
# Intentar autenticarse con una credencial encontrada
$cred = New-Object System.Management.Automation.PSCredential(
    "adlab\Administrator", 
    (ConvertTo-SecureString "P@ssAdmin123!" -AsPlainText -Force)
)

# Probar acceso a recurso protegido
Get-ADUser -Filter * -Credential $cred | Select-Object Name
```

Si funciona, las credenciales quedan confirmadas como válidas.

## Paso 3: Indicadores de Compromiso (IoCs)

### En DC01 (Visor de eventos → Seguridad):

Como indicamos anteriormente es normal que un usuario entre en las carpetas comaprtidas por lo que debemos ir un paso mas allá y fijarnos en aspectos como el tipo de usuario que consulta, la frecuencia de consulta... es decir, comportamientos anomalos dentgro de la propia consulta de la carpeta compartida.

Event ID 5145 — Detailed File Share Access

| Campo | Patrón sospechoso |
|-------|-------------------|
| **Usuario** | Usuario de dominio normal (no admin) |
| **Archivo** | Script/config: `.ps1`, `.bat`, `.ini`, `.config`, `.xml` |
| **Compartida** | `\\DC01\scripts`, `\\SERVER\dev$`, `\\FILESERVER\backup` |
| **Frecuencia** | ALERTA: 5+ accesos en <1 min, CRÍTICA: 20+ en <3 min |
| **IP origen** | Dirección de equipo cliente inesperada |
| **Acceso** | `READ_CONTROL`, `ReadData`, `ReadAttributes` |

Ejemplo real del log:
```
Event ID: 5145
Usuario: ADLAB\pedri
Archivo: backup.ps1, config.ini, sync.bat, webserver.config
Compartida: \\DC01\scripts
IP origen: 100.100.100.40
Tiempo: 09/07/2026 20:13:00 - 20:14:30
Número de accesos: 15 en ~90 segundos → ALERTA GRAVE
```

![Evento 5145 en el Visor de eventos de DC01, detallando el acceso de ADLAB\pedri a sync.bat en \\*\Scripts desde 100.100.100.40](<img/Visualizamos los logs generados.png>)

Señales de alarma:

1. Acceso rápido a múltiples archivos (especialmente `.ps1`, `.bat`, `.config`)
2. Usuario normal accediendo a compartidas administrativas (`dev$`, `backup$`, `admin$`)
3. Acceso a archivos de configuración seguido de logon como cuenta diferente
4. Patrón de enumeración: mismo usuario, múltiples archivos, ventana temporal corta
5. Acceso a SYSVOL + NETLOGON (reconocimiento de GPO)

## Paso 4: Script de Detección PowerShell

```powershell
# DetectCredentialsInShares.ps1
# Detecta enumeración de credenciales en compartidas via Event ID 5145

param(
    [int]$HoursBack = 24,
    [int]$AlertMediaThreshold = 5,      # 5+ accesos en <1 min
    [int]$AlertGraveThreshold = 20,     # 20+ accesos en <3 min
    [string]$SuspiciousFileTypes = "ps1|bat|cmd|ini|config|xml|conf"
)

Write-Host "[*] Buscando acceso a archivos de configuración en compartidas..." -ForegroundColor Cyan

# Buscar Event ID 5145 (Detailed File Share)
$startTime = (Get-Date).AddHours(-$HoursBack)
$events = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    ID        = 5145
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "[!] No se encontraron eventos 5145" -ForegroundColor Yellow
    return
}

# Agrupar por usuario
$userAccess = @{}

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    # Extraer información
    $user = ($eventData | Where-Object {$_.Name -eq "SubjectUserName"}).InnerText
    $file = ($eventData | Where-Object {$_.Name -eq "RelativeTargetName"}).InnerText
    $time = $event.TimeCreated
    
    # Filtrar por tipos de archivo sospechosos
    if ($file -notmatch $SuspiciousFileTypes) {
        continue
    }
    
    # Agrupar por usuario
    if (-not $userAccess[$user]) {
        $userAccess[$user] = @()
    }
    
    $userAccess[$user] += @{
        File = $file
        Time = $time
    }
}

# Analizar patrones de enumeración
foreach ($user in $userAccess.Keys) {
    $accessList = $userAccess[$user] | Sort-Object -Property Time
    
    # Buscar ventanas de tiempo cortas con muchos accesos
    for ($i = 0; $i -lt $accessList.Count; $i++) {
        $currentTime = $accessList[$i].Time
        
        # Contar accesos en ventana de 1 minuto
        $oneMinWindow = $accessList | Where-Object {
            [Math]::Abs(($_.Time - $currentTime).TotalSeconds) -le 60
        }
        
        # Contar accesos en ventana de 3 minutos
        $threeMinWindow = $accessList | Where-Object {
            [Math]::Abs(($_.Time - $currentTime).TotalSeconds) -le 180
        }
        
        # Alertas
        if ($oneMinWindow.Count -ge $AlertMediaThreshold) {
            Write-Host "[ALERTA MEDIA] Usuario '$user' accedió a $($oneMinWindow.Count) archivos en <1 minuto" -ForegroundColor Yellow
            Write-Host "    Archivos: $($oneMinWindow.File -join ', ')" -ForegroundColor Yellow
        }
        
        if ($threeMinWindow.Count -ge $AlertGraveThreshold) {
            Write-Host "[ALERTA GRAVE] Usuario '$user' accedió a $($threeMinWindow.Count) archivos en <3 minutos" -ForegroundColor Red
            Write-Host "    POSIBLE ENUMERACIÓN DE CREDENCIALES" -ForegroundColor Red
            Write-Host "    Archivos: $($threeMinWindow.File -join ', ')" -ForegroundColor Red
        }
    }
}
```

Uso:
```powershell
.\DetectCredentialsInShares.ps1 -HoursBack 24 -AlertMediaThreshold 5 -AlertGraveThreshold 20
```

## Mitigación y Hardening

### 1. Auditoría de compartidas

```powershell
# Listar todas las compartidas y sus permisos
Get-SmbShare | Select-Object Name, Path

# Ver permisos NTFS
icacls C:\Scripts
```

### 2. Restringir acceso

```powershell
# Usar grupos específicos en lugar de "Todos"
Revoke-SmbShareAccess -Name "scripts" -AccountName "Todos" -Force
Grant-SmbShareAccess -Name "scripts" -AccountName "ADLAB\Administradores" -AccessRight Full
```

### 3. No almacenar credenciales en texto plano

- Usar **Azure Key Vault** para credenciales
- Usar **Managed Service Identity (MSI)** en Azure
- Usar **DPAPI** para encriptación local
- Usar **credential managers** (Keepass, 1Password)

### 4. Monitorear compartidas administrativas

```powershell
# Auditar acceso a compartidas ocultas ($)
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
```

### 5. Escaneo periódico de credenciales

```powershell
# Script semanal para buscar credenciales en compartidas
Get-ChildItem -Path "\\*\*$" -Recurse -Filter "*.ps1", "*.bat", "*.config" | 
    ForEach-Object { Select-String -Path $_.FullName -Pattern "password|pwd|credential" }
```

## Notas importantes

1. **Living Off the Land**: `findstr` es una herramienta nativa de Windows. No genera alertas de "herramientas sospechosas" instaladas, debemos tener cuidado y ver como se utiliza.

2. **Amplitud del problema**: en entornos grandes, pueden haber miles de compartidas. Un ataque realista usaría herramientas como **PowerView** o **CrackMapExec** para automatizar la búsqueda.

3. **Diferencia de escalas**: 
   - 1-2 accesos: normal (usuarios normales consultando scripts)
   - 5-10 accesos rápidos: sospechoso (podría ser administrador)
   - 20+ en 3 min: casi seguro que es enumeración maliciosa

4. **Falsos positivos**: scripts de automatización legítimos también pueden generar muchos accesos. Necesita **baselining** de comportamiento normal.

## Referencias

- [Microsoft: Detailed File Share](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-file-share)
- [SANS: Finding Passwords in Scripts](https://www.sans.org/reading-room/)
- [adsecurity.org: Credentials in Shares](https://adsecurity.org/)

**Estado**: Completado  
**Evidencia generada**: Event ID 5145 (Detailed File Share) 
