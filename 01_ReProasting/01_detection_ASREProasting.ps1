# Módulo 1: Detección AS-REProasting
function Get-ASREProastingAttempts {
    param(
        [int]$HorasAtras = 24
    )

    $tiempo = (Get-Date).AddHours(-$HorasAtras)
    
    $eventos = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4768
        StartTime = $tiempo
    } -ErrorAction SilentlyContinue

    $alertas = @()

    foreach ($evento in $eventos) {
        $xml = [xml]$evento.ToXml()
        $datos = $xml.Event.EventData.Data

        $cuenta     = ($datos | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $cifrado    = ($datos | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
        $preauth    = ($datos | Where-Object { $_.Name -eq 'PreAuthType' }).'#text'
        $ipOrigen   = ($datos | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $resultado  = ($datos | Where-Object { $_.Name -eq 'Status' }).'#text'

        # Firma del AS-REProasting: sin preauth (0) y cifrado RC4 (0x17)
        if ($preauth -eq '0' -and $cifrado -eq '0x17') {
            $alertas += [PSCustomObject]@{
                Fecha    = $evento.TimeCreated
                Cuenta   = $cuenta
                Cifrado  = $cifrado
                PreAuth  = $preauth
                IPOrigen = $ipOrigen
                Severdad = 'ALTA'
                Ataque   = 'AS-REProasting'
            }
        }
    }

    return $alertas
}

# Test
$resultado = Get-ASREProastingAttempts -HorasAtras 24
if ($resultado) {
    Write-Host "`n[!] AS-REProasting detectado:" -ForegroundColor Red
    $resultado | Format-Table -AutoSize
} else {
    Write-Host "`n[+] Sin alertas de AS-REProasting" -ForegroundColor Green
}
