<#
.SYNOPSIS
    Detect-KerberosConstrainedDelegation.ps1
    Detecta abuso de Kerberos Constrained Delegation (S4U2Self / S4U2Proxy)
    mediante el análisis del campo "Transmitted Services" en el Event ID 4769,
    correlacionado con eventos 4624.

.DESCRIPTION
    Ataque 09 del proyecto AD_Attack_Detection Lab.

    Lógica de detección:
    1. Busca Event ID 4769 (Kerberos Service Ticket Operations) en el log Security.
    2. Filtra aquellos cuyo campo TransmittedServices NO esté vacío -> indicio de
       que el ticket se generó mediante un proceso S4U (delegación), no un logon normal.
    3. Clasifica la severidad según si la cuenta origen de la delegación aparece
       en la lista de cuentas de servicio conocidas/vigiladas, y si el destino
       es una cuenta o equipo sensible (ej. Domain Controllers).
    4. Detecta además ráfagas de eventos 4769 con ResultCode 0x6
       (KDC_ERR_C_PRINCIPAL_UNKNOWN) para la misma cuenta origen en poco tiempo,
       indicio de enumeración/fuerza bruta de nombres de usuario a impersonar.
    5. Correlaciona con eventos 4624 (Logon) cercanos en el tiempo desde la misma IP.

.PARAMETER StartTime
    Fecha/hora desde la que analizar el log. Por defecto, últimas 24 horas.

.PARAMETER OutputPath
    Ruta del informe de salida (CSV). Por defecto, escritorio del usuario actual.

.PARAMETER SensitiveAccounts
    Lista de cuentas privilegiadas a vigilar especialmente si aparecen impersonadas
    (campo TargetUserName en eventos correlacionados, o dentro del propio 4624).

.EXAMPLE
    .\Detect-KerberosConstrainedDelegation.ps1

.EXAMPLE
    .\Detect-KerberosConstrainedDelegation.ps1 -StartTime (Get-Date).AddDays(-1) -OutputPath "C:\Reports\delegation.csv"

.NOTES
    Requiere ejecutarse en el DC (o con acceso remoto al log Security del DC)
    y permisos para leer el registro de eventos de Seguridad.
    Requiere que la auditoría "Kerberos Service Ticket Operations" y
    "Kerberos Authentication Service" estén activas (Success).
#>

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddHours(-24),

    [string]$OutputPath = "$env:USERPROFILE\Desktop\Report_KerberosConstrainedDelegation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [string[]]$SensitiveAccounts = @('administrador','administrator','krbtgt'),

    [int]$BruteForceThreshold = 3,

    [int]$BruteForceWindowSeconds = 60
)

$ErrorActionPreference = 'Stop'

function Get-EventXmlValue {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [string]$Name
    )
    try {
        [xml]$xml = $Event.ToXml()
        $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }
        return $node.'#text'
    }
    catch {
        return $null
    }
}

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " AD_Attack_Detection Lab - Detector 09: Kerberos Constrained Delegation" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "Analizando eventos desde: $StartTime" -ForegroundColor Gray
Write-Host ""

$findings = New-Object System.Collections.Generic.List[Object]

# -----------------------------------------------------------------------
# 1) EVENTOS 4769 CON "SERVICIOS TRANSITADOS" NO VACIO -> DELEGACION EN USO
# -----------------------------------------------------------------------
Write-Host "[*] Buscando eventos 4769 (Kerberos Service Ticket Operations)..." -ForegroundColor Yellow

try {
    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769) and TimeCreated[@SystemTime&gt;='$($StartTime.ToUniversalTime().ToString("o"))']]]
    </Select>
  </Query>
</QueryList>
"@
    $events4769 = Get-WinEvent -FilterXml $filterXml -ErrorAction Stop
}
catch {
    Write-Host "[!] No se encontraron eventos 4769 en el rango indicado, o no hay permisos suficientes." -ForegroundColor DarkYellow
    $events4769 = @()
}

$delegationFailCounter = @{}

foreach ($ev in $events4769) {

    $accountName      = Get-EventXmlValue -Event $ev -Name 'TargetUserName'
    $serviceName      = Get-EventXmlValue -Event $ev -Name 'ServiceName'
    $ipAddress        = Get-EventXmlValue -Event $ev -Name 'IpAddress'
    $resultCode       = Get-EventXmlValue -Event $ev -Name 'Status'
    $transitedServices= Get-EventXmlValue -Event $ev -Name 'TransmittedServices'
    $ticketEncType    = Get-EventXmlValue -Event $ev -Name 'TicketEncryptionType'

    # --- 1a) Ráfagas de fallos KDC_ERR_C_PRINCIPAL_UNKNOWN (0x6) ---------
    if ($resultCode -eq '0x6') {
        $key = $accountName
        if (-not $delegationFailCounter.ContainsKey($key)) {
            $delegationFailCounter[$key] = New-Object System.Collections.Generic.List[datetime]
        }
        $delegationFailCounter[$key].Add($ev.TimeCreated)
    }

    # --- 1b) Deteccion principal: TransmittedServices poblado ------------
    if (-not [string]::IsNullOrWhiteSpace($transitedServices) -and $transitedServices -ne '-') {

        $isSensitiveTarget = $false
        foreach ($sa in $SensitiveAccounts) {
            if ($serviceName -match [regex]::Escape($sa)) { $isSensitiveTarget = $true }
        }

        $severity = if ($isSensitiveTarget) { 'CRITICA' } else { 'ALTA' }

        $findings.Add([PSCustomObject]@{
            Timestamp            = $ev.TimeCreated
            EventID              = 4769
            Tipo                 = 'S4U2Proxy detectado (Transited Services no vacio)'
            CuentaOrigenPeticion = $accountName
            ServicioDestino      = $serviceName
            ServiciosTransitados = $transitedServices
            IPOrigen             = $ipAddress
            TipoCifrado          = $ticketEncType
            Severidad            = $severity
            Detalle              = "El ticket para '$serviceName' fue emitido via delegacion; la cuenta '$transitedServices' actuo como intermediaria."
        })
    }
}

# --- 1c) Reportar rafagas de fallos 0x6 (enumeracion de usuarios) --------
foreach ($account in $delegationFailCounter.Keys) {
    $timestamps = $delegationFailCounter[$account] | Sort-Object
    for ($i = 0; $i -lt $timestamps.Count; $i++) {
        $windowEnd = $timestamps[$i].AddSeconds($BruteForceWindowSeconds)
        $countInWindow = ($timestamps | Where-Object { $_ -ge $timestamps[$i] -and $_ -le $windowEnd }).Count
        if ($countInWindow -ge $BruteForceThreshold) {
            $findings.Add([PSCustomObject]@{
                Timestamp            = $timestamps[$i]
                EventID              = 4769
                Tipo                 = 'Posible enumeracion de usuarios via S4U2Self (multiples KDC_ERR_C_PRINCIPAL_UNKNOWN)'
                CuentaOrigenPeticion = $account
                ServicioDestino      = 'N/A'
                ServiciosTransitados = 'N/A'
                IPOrigen             = 'N/A'
                TipoCifrado          = 'N/A'
                Severidad            = 'MEDIA'
                Detalle              = "$countInWindow intentos fallidos (0x6) en $BruteForceWindowSeconds segundos para la cuenta '$account'."
            })
            break
        }
    }
}

# -----------------------------------------------------------------------
# 2) CORRELACION CON EVENTOS 4624 (LOGON) DESDE LAS MISMAS IP DE ORIGEN
# -----------------------------------------------------------------------
Write-Host "[*] Buscando eventos 4624 (Logon) para correlacionar..." -ForegroundColor Yellow

try {
    $filterXml4624 = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[@SystemTime&gt;='$($StartTime.ToUniversalTime().ToString("o"))']]]
    </Select>
  </Query>
</QueryList>
"@
    $events4624 = Get-WinEvent -FilterXml $filterXml4624 -ErrorAction Stop
}
catch {
    $events4624 = @()
}

foreach ($ev in $events4624) {

    $logonType     = Get-EventXmlValue -Event $ev -Name 'LogonType'
    $targetUser    = Get-EventXmlValue -Event $ev -Name 'TargetUserName'
    $ipAddress     = Get-EventXmlValue -Event $ev -Name 'IpAddress'
    $logonProcess  = Get-EventXmlValue -Event $ev -Name 'LogonProcessName'
    $impersonation = Get-EventXmlValue -Event $ev -Name 'ImpersonationLevel'

    # Solo nos interesan logons de red (3) de cuentas sensibles, via Kerberos,
    # con nivel de suplantacion (impersonation) explicito
    $isSensitiveUser = $false
    foreach ($sa in $SensitiveAccounts) {
        if ($targetUser -match [regex]::Escape($sa)) { $isSensitiveUser = $true }
    }

    if ($logonType -eq '3' -and $isSensitiveUser -and $logonProcess -eq 'Kerberos') {

        # Buscamos si hay un 4769 con Transited Services no vacio en una ventana de +/- 5 min
        $windowStart = $ev.TimeCreated.AddMinutes(-5)
        $windowEnd   = $ev.TimeCreated.AddMinutes(5)

        $relatedDelegation = $findings | Where-Object {
            $_.EventID -eq 4769 -and
            $_.Tipo -like 'S4U2Proxy*' -and
            $_.Timestamp -ge $windowStart -and $_.Timestamp -le $windowEnd
        }

        $severity = if ($relatedDelegation) { 'CRITICA' } else { 'INFORMATIVA' }
        $detalle  = if ($relatedDelegation) {
            "Logon de cuenta sensible '$targetUser' desde $ipAddress, CORRELACIONADO con evento de delegacion (S4U2Proxy) en ventana de +/-5 min. Cuenta delegante: $($relatedDelegation[0].CuentaOrigenPeticion)"
        } else {
            "Logon de cuenta sensible '$targetUser' desde $ipAddress via Kerberos, tipo red. Revisar si corresponde a un logon legitimo o si falta el 4769 relacionado (verificar auditoria)."
        }

        $findings.Add([PSCustomObject]@{
            Timestamp            = $ev.TimeCreated
            EventID              = 4624
            Tipo                 = 'Logon de cuenta sensible (tipo Red, via Kerberos)'
            CuentaOrigenPeticion = $targetUser
            ServicioDestino      = 'N/A'
            ServiciosTransitados = if ($impersonation -eq '%%1841') { 'Suplantacion' } else { $impersonation }
            IPOrigen             = $ipAddress
            TipoCifrado          = 'N/A'
            Severidad            = $severity
            Detalle              = $detalle
        })
    }
}

# -----------------------------------------------------------------------
# 3) INFORME FINAL
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
if ($findings.Count -eq 0) {
    Write-Host "[OK] No se detectaron indicios de abuso de Kerberos Constrained Delegation." -ForegroundColor Green
}
else {
    Write-Host "[!] Se encontraron $($findings.Count) hallazgo(s):" -ForegroundColor Red
    Write-Host ""

    $findings | Sort-Object Timestamp | Format-Table -AutoSize -Wrap `
        Timestamp, EventID, Severidad, CuentaOrigenPeticion, ServicioDestino, ServiciosTransitados, IPOrigen

    $findings | Sort-Object Timestamp | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "[*] Informe exportado a: $OutputPath" -ForegroundColor Cyan

    $critCount = ($findings | Where-Object { $_.Severidad -eq 'CRITICA' }).Count
    if ($critCount -gt 0) {
        Write-Host "[!!] $critCount hallazgo(s) de severidad CRITICA - revisar de inmediato." -ForegroundColor Magenta
    }
}
Write-Host "=====================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------
# Devuelve el objeto de hallazgos para poder integrarlo en un script
# unificado (ej. AD-ThreatDetector.ps1) que recorra todos los detectores
# y consolide un unico reporte diario por correo.
# -----------------------------------------------------------------------
return $findings
