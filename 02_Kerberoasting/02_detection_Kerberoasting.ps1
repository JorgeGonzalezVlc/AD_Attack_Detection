# ============================================================
# detection.ps1 — Kerberoasting Detection Module
# Part of AD_Attack_Detection toolkit
# https://github.com/JorgeGonzalezVlc/AD_Attack_Detection
# ============================================================

function Get-KerberoastingAttempts {
    <#
    .SYNOPSIS
        Detects Kerberoasting attempts by analyzing Event ID 4769.

    .DESCRIPTION
        Searches the Security event log for Kerberos service ticket
        requests using weak RC4 encryption (0x17). While not every
        RC4 ticket request is malicious, a high volume of requests
        from a single account in a short time window is a strong
        indicator of Kerberoasting.

    .PARAMETER HorasAtras
        Number of hours back to search. Default: 24.

    .PARAMETER UmbralSolicitudes
        Minimum number of RC4 ticket requests from the same account
        within the time window to trigger an alert. Default: 3.

    .EXAMPLE
        Get-KerberoastingAttempts -HorasAtras 24
    #>

    param(
        [int]$HorasAtras = 24,
        [int]$UmbralSolicitudes = 3
    )

    $tiempo = (Get-Date).AddHours(-$HorasAtras)

    $eventos = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4769
        StartTime = $tiempo
    } -ErrorAction SilentlyContinue

    $solicitudesRC4 = @()

    foreach ($evento in $eventos) {
        $xml   = [xml]$evento.ToXml()
        $datos = $xml.Event.EventData.Data

        $cuenta   = ($datos | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $servicio = ($datos | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $cifrado  = ($datos | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
        $ipOrigen = ($datos | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $resultado = ($datos | Where-Object { $_.Name -eq 'Status' }).'#text'

        # Ignorar tickets de la propia cuenta de equipo (terminan en $)
        if ($cuenta -like '*$') { continue }

        # Cifrado RC4 = señal de posible Kerberoasting
        if ($cifrado -eq '0x17' -and $servicio -ne 'krbtgt') {
            $solicitudesRC4 += [PSCustomObject]@{
                Fecha     = $evento.TimeCreated
                Cuenta    = $cuenta
                Servicio  = $servicio
                Cifrado   = $cifrado
                IPOrigen  = $ipOrigen
            }
        }
    }

    $alertas = @()

    # Agrupar por cuenta solicitante para detectar volumen anomalo
    $agrupado = $solicitudesRC4 | Group-Object -Property Cuenta

    foreach ($grupo in $agrupado) {
        if ($grupo.Count -ge $UmbralSolicitudes) {
            $serviciosUnicos = ($grupo.Group.Servicio | Select-Object -Unique) -join ', '
            $ipsUnicas       = ($grupo.Group.IPOrigen | Select-Object -Unique) -join ', '

            $alertas += [PSCustomObject]@{
                Fecha           = ($grupo.Group | Sort-Object Fecha -Descending | Select-Object -First 1).Fecha
                CuentaAtacante  = $grupo.Name
                NumSolicitudes  = $grupo.Count
                ServiciosUnicos = $serviciosUnicos
                IPOrigen        = $ipsUnicas
                Severidad       = 'ALTA'
                Ataque          = 'Kerberoasting'
            }
        }
    }

    return $alertas
}

# --- Standalone execution ---
$resultado = Get-KerberoastingAttempts -HorasAtras 24 -UmbralSolicitudes 1

if ($resultado) {
    Write-Host "`n[!] Kerberoasting detectado:" -ForegroundColor Red
    $resultado | Format-Table -AutoSize
} else {
    Write-Host "`n[+] Sin alertas de Kerberoasting en las ultimas 24h" -ForegroundColor Green
}
