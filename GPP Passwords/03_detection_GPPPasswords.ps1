# ============================================================
# detection.ps1 — GPP Passwords Detection Module
# Part of AD_Attack_Detection toolkit
# https://github.com/JorgeGonzalezVlc/AD_Attack_Detection
# ============================================================

function Get-GPPPasswordAttempts {
    <#
    .SYNOPSIS
        Detects GPP Passwords exploitation attempts by analyzing Event ID 5145.

    .DESCRIPTION
        Searches the Security event log for access to the SYSVOL Preferences
        subfolders (ScheduledTasks, Groups, Services, Drives, DataSources,
        Printers) where GPP XML files historically stored encrypted
        passwords (cpassword). Reading these specific subfolders is
        very unusual for a normal user — domain clients read SYSVOL
        constantly for GPO application, but rarely browse directly
        into the Preferences folders.

        Requires:
          - Advanced Audit Policy: Object Access > Audit Detailed
            File Share = Success, enabled via GPO on Domain Controllers
          - A SACL configured on C:\Windows\SYSVOL\domain auditing
            read access for "Everyone" or "Authenticated Users"

    .PARAMETER HorasAtras
        Number of hours back to search. Default: 24.

    .EXAMPLE
        Get-GPPPasswordAttempts -HorasAtras 24
    #>

    param(
        [int]$HorasAtras = 24
    )

    $tiempo = (Get-Date).AddHours(-$HorasAtras)

    # Subcarpetas de Preferences donde GPP guardaba credenciales
    $rutasSospechosas = @(
        'ScheduledTasks',
        'Groups',
        'Services',
        'Drives',
        'DataSources',
        'Printers'
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

        $cuenta      = ($datos | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $ipOrigen    = ($datos | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $recurso     = ($datos | Where-Object { $_.Name -eq 'ShareName' }).'#text'
        $rutaRelativa = ($datos | Where-Object { $_.Name -eq 'RelativeTargetName' }).'#text'
        $accesos     = ($datos | Where-Object { $_.Name -eq 'AccessList' }).'#text'

        # Solo nos interesa el recurso SYSVOL
        if ($recurso -notlike '*SYSVOL*') { continue }

        # Comprobar si la ruta accedida toca alguna subcarpeta sospechosa
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

# --- Standalone execution ---
$resultado = Get-GPPPasswordAttempts -HorasAtras 24

if ($resultado) {
    Write-Host "`n[!] Posible busqueda de GPP Passwords detectada:" -ForegroundColor Yellow
    $resultado | Format-Table -AutoSize
} else {
    Write-Host "`n[+] Sin alertas de GPP Passwords en las ultimas 24h" -ForegroundColor Green
}
