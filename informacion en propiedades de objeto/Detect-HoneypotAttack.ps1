#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect-HoneypotAttack.ps1
    Detecta intentos de logon en cuenta honeypot (Event ID 4624 y 4625)
    
.DESCRIPTION
    Monitorea intentos de logon exitosos y fallidos en el usuario honeypot.
    Si alguien intenta logarse con la contraseña FALSA de la Description,
    generará Event ID 4625 (fallo) = ALERTA
    
    Si se loguea como la cuenta honeypot con contraseña real = Event ID 4624 (normal)
    Si se loguea con contraseña falsa = Event ID 4625 (ATACANTE DETECTADO)

.PARAMETER HoneypotUser
    Nombre del usuario honeypot (default: honeybot)
    
.PARAMETER HoursBack
    Número de horas hacia atrás a auditar (default: 24)
    
.PARAMETER OutputPath
    Ruta para guardar reporte (default: C:\Reports\)

.EXAMPLE
    .\Detect-HoneypotAttack.ps1 -HoneypotUser "honeybot" -HoursBack 24
#>

param(
    [string]$HoneypotUser = "honeybot",
    [int]$HoursBack = 24,
    [string]$OutputPath = "C:\Reports"
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# FUNCIONES
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "ALERT")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    $Colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "ALERT"   = "Red"
    }
    
    Write-Host $LogMessage -ForegroundColor $Colors[$Level]
}

function Parse-Event4624 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated = $Event.TimeCreated
            User        = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
            Domain      = ($eventData | Where-Object {$_.Name -eq "TargetDomainName"}).InnerText
            LogonType   = ($eventData | Where-Object {$_.Name -eq "LogonType"}).InnerText
            IP          = ($eventData | Where-Object {$_.Name -eq "IpAddress"}).InnerText
            Port        = ($eventData | Where-Object {$_.Name -eq "IpPort"}).InnerText
        }
        
        return $data
    } catch {
        return $null
    }
}

function Parse-Event4625 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated      = $Event.TimeCreated
            User             = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
            Domain           = ($eventData | Where-Object {$_.Name -eq "TargetDomainName"}).InnerText
            LogonType        = ($eventData | Where-Object {$_.Name -eq "LogonType"}).InnerText
            FailureReason    = ($eventData | Where-Object {$_.Name -eq "FailureReason"}).InnerText
            Status           = ($eventData | Where-Object {$_.Name -eq "Status"}).InnerText
            SubStatus        = ($eventData | Where-Object {$_.Name -eq "SubStatus"}).InnerText
            IP               = ($eventData | Where-Object {$_.Name -eq "IpAddress"}).InnerText
            Port             = ($eventData | Where-Object {$_.Name -eq "IpPort"}).InnerText
        }
        
        return $data
    } catch {
        return $null
    }
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    Write-Log "========================================" "INFO"
    Write-Log "Honeypot Attack Detector v1.0" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    Write-Log "Parámetros:" "INFO"
    Write-Log "  - Usuario honeypot: $HoneypotUser" "INFO"
    Write-Log "  - Período: $HoursBack horas" "INFO"
    Write-Log ""
    
    $startTime = (Get-Date).AddHours(-$HoursBack)
    
    # ========================================================================
    # BUSCAR EVENT ID 4625 (FALLIDOS) - ALERTA CRÍTICA
    # ========================================================================
    
    Write-Log "Buscando intentos fallidos de logon (Event ID 4625)..." "INFO"
    
    $failedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4625
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $honeypotFailures = @()
    
    if ($failedEvents) {
        foreach ($event in $failedEvents) {
            $parsed = Parse-Event4625 -Event $event
            
            if ($parsed -and $parsed.User -eq $HoneypotUser) {
                $honeypotFailures += $parsed
            }
        }
    }
    
    Write-Log ""
    
    if ($honeypotFailures.Count -gt 0) {
        Write-Log "🔴 [CRÍTICA] INTENTOS FALLIDOS DETECTADOS EN HONEYPOT" "ALERT"
        Write-Log "   Usuario: $HoneypotUser" "ALERT"
        Write-Log "   Intentos fallidos: $($honeypotFailures.Count)" "ALERT"
        Write-Log ""
        
        foreach ($failure in $honeypotFailures) {
            Write-Log "   ════════════════════════════════════" "ALERT"
            Write-Log "   Hora: $($failure.TimeCreated)" "ALERT"
            Write-Log "   Usuario intentado: $($failure.Domain)\$($failure.User)" "ALERT"
            Write-Log "   Tipo de logon: $($failure.LogonType)" "ALERT"
            Write-Log "   Razón del fallo: $($failure.FailureReason)" "ALERT"
            Write-Log "   IP origen: $($failure.IP)" "ALERT"
            Write-Log "   Puerto origen: $($failure.Port)" "ALERT"
            Write-Log "   Status: $($failure.Status)" "ALERT"
            Write-Log ""
        }
    } else {
        Write-Log "✓ No se detectaron intentos fallidos de logon en honeypot" "SUCCESS"
    }
    
    Write-Log ""
    
    # ========================================================================
    # BUSCAR EVENT ID 4624 (EXITOSOS) - INFORMACIÓN
    # ========================================================================
    
    Write-Log "Buscando logons exitosos de cuentas de servicio (Event ID 4624)..." "INFO"
    
    $successEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4624
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $serviceAccountLogons = @()
    $suspiciousAccounts = @("svc_app", "svc_backup", "svc_sql", "svc_exchange", "admin_temp")
    
    if ($successEvents) {
        foreach ($event in $successEvents) {
            $parsed = Parse-Event4624 -Event $event
            
            if ($parsed) {
                foreach ($account in $suspiciousAccounts) {
                    if ($parsed.User -eq $account) {
                        $serviceAccountLogons += $parsed
                        break
                    }
                }
            }
        }
    }
    
    if ($serviceAccountLogons.Count -gt 0) {
        Write-Log "⚠️  LOGONS EXITOSOS DE CUENTAS DE SERVICIO" "WARN"
        Write-Log "   Total de logons: $($serviceAccountLogons.Count)" "WARN"
        Write-Log ""
        
        $groupedByAccount = $serviceAccountLogons | Group-Object -Property User
        
        foreach ($group in $groupedByAccount) {
            Write-Log "   Usuario: $($group.Name) - $($group.Count) logons" "WARN"
            
            foreach ($logon in $group.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 3) {
                Write-Log "     • $($logon.TimeCreated) desde $($logon.IP)" "WARN"
            }
            Write-Log ""
        }
    } else {
        Write-Log "✓ No se detectaron logons sospechosos de cuentas de servicio" "SUCCESS"
    }
    
    Write-Log ""
    
    # ========================================================================
    # RESUMEN
    # ========================================================================
    
    Write-Log "========================================" "INFO"
    Write-Log "RESUMEN DE DETECCIÓN" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    if ($honeypotFailures.Count -gt 0) {
        Write-Log "🔴 AMENAZA DETECTADA" "ALERT"
        Write-Log "   - $($honeypotFailures.Count) intentos fallidos en honeypot '$HoneypotUser'" "ALERT"
        Write-Log "   - Esto indica que alguien encontró las credenciales falsas y las está usando" "ALERT"
        Write-Log "   - ACCIÓN RECOMENDADA: Investigar las IPs de origen inmediatamente" "ALERT"
    } else {
        Write-Log "✓ No se detectaron intentos en el honeypot" "SUCCESS"
    }
    
    if ($serviceAccountLogons.Count -gt 0) {
        Write-Log "⚠️  ACTIVIDAD ANÓMALA EN CUENTAS DE SERVICIO" "WARN"
        Write-Log "   - $($serviceAccountLogons.Count) logons de cuentas de servicio detectados" "WARN"
        Write-Log "   - Revisar si estos logons son legítimos" "WARN"
    } else {
        Write-Log "✓ Cuentas de servicio sin actividad anómala" "SUCCESS"
    }
    
    Write-Log ""
    Write-Log "========================================" "INFO"
    Write-Log "Análisis completado - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "========================================" "INFO"
    
    # Guardar resultados
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputPath "HoneypotDetection_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    
    if ($honeypotFailures.Count -gt 0) {
        $honeypotFailures | Export-Csv -Path $reportFile -NoTypeInformation
        Write-Log "Reporte guardado en: $reportFile" "SUCCESS"
    }
    
    return @{
        HoneypotFailures = $honeypotFailures
        ServiceLogons    = $serviceAccountLogons
    }
}

# Ejecutar
Main
