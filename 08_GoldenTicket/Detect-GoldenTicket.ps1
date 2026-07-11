#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect-GoldenTicket.ps1
    Detecta Golden Tickets mediante Event IDs 4768, 4769, 4776
    
.DESCRIPTION
    Monitorea eventos Kerberos para detectar:
    - Event ID 4768 (TGT Request) - Solicitud de Ticket Granting Ticket
    - Event ID 4769 (Service Ticket Request) - Solicitud de tickets de servicio
    - Event ID 4776 (NTLM Logon) - Validación de credenciales NTLM
    
    El Golden Ticket es un ataque post-DCSync que permite acceso
    permanente al dominio como cualquier usuario (incluido admin).

.PARAMETER HoursBack
    Número de horas hacia atrás a auditar (default: 24)
    
.PARAMETER OutputPath
    Ruta para guardar reporte (default: C:\Reports\)

.EXAMPLE
    .\Detect-GoldenTicket.ps1 -HoursBack 24
    .\Detect-GoldenTicket.ps1 -HoursBack 48 -OutputPath "C:\Security"
#>

param(
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

function Parse-Event4768 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated       = $Event.TimeCreated
            EventID           = 4768
            User              = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
            Domain            = ($eventData | Where-Object {$_.Name -eq "TargetDomainName"}).InnerText
            ServiceName       = ($eventData | Where-Object {$_.Name -eq "ServiceName"}).InnerText
            TicketEncryption  = ($eventData | Where-Object {$_.Name -eq "TicketEncryptionType"}).InnerText
            ResultCode        = ($eventData | Where-Object {$_.Name -eq "Status"}).InnerText
        }
        
        return $data
    } catch {
        return $null
    }
}

function Parse-Event4769 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated       = $Event.TimeCreated
            EventID           = 4769
            User              = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
            Domain            = ($eventData | Where-Object {$_.Name -eq "TargetDomainName"}).InnerText
            ServiceName       = ($eventData | Where-Object {$_.Name -eq "ServiceName"}).InnerText
            ServiceID         = ($eventData | Where-Object {$_.Name -eq "ServiceID"}).InnerText
            ResultCode        = ($eventData | Where-Object {$_.Name -eq "Status"}).InnerText
        }
        
        return $data
    } catch {
        return $null
    }
}

function Parse-Event4776 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated       = $Event.TimeCreated
            EventID           = 4776
            User              = ($eventData | Where-Object {$_.Name -eq "TargetUserName"}).InnerText
            WorkStation       = ($eventData | Where-Object {$_.Name -eq "Workstation"}).InnerText
            Status            = ($eventData | Where-Object {$_.Name -eq "Status"}).InnerText
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
    Write-Log "Golden Ticket Detector v1.0" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    Write-Log "Parámetros:" "INFO"
    Write-Log "  - Período: $HoursBack horas" "INFO"
    Write-Log "  - Ruta de salida: $OutputPath" "INFO"
    Write-Log ""
    
    $startTime = (Get-Date).AddHours(-$HoursBack)
    
    # ========================================================================
    # BUSCAR EVENT ID 4768 (TGT Request)
    # ========================================================================
    
    Write-Log "Buscando Event ID 4768 (TGT Request)..." "INFO"
    
    $events4768 = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4768
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $suspiciousTGT = @()
    
    if ($events4768) {
        Write-Log "Se encontraron $($events4768.Count) eventos 4768" "SUCCESS"
        
        foreach ($event in $events4768) {
            $parsed = Parse-Event4768 -Event $event
            
            if ($parsed) {
                # Señales de alarma:
                # 1. Solicitud de TGT a krbtgt desde usuario normal
                # 2. Múltiples solicitudes rápidamente
                # 3. Usuario no admin solicitando TGT
                
                if ($parsed.ServiceName -match "krbtgt" -or $parsed.User -match "krbtgt") {
                    $suspiciousTGT += $parsed
                }
            }
        }
    } else {
        Write-Log "No se encontraron eventos 4768" "WARN"
    }
    
    Write-Log ""
    
    # ========================================================================
    # BUSCAR EVENT ID 4769 (Service Ticket Request)
    # ========================================================================
    
    Write-Log "Buscando Event ID 4769 (Service Ticket Request)..." "INFO"
    
    $events4769 = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4769
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $suspiciousServiceTickets = @()
    
    if ($events4769) {
        Write-Log "Se encontraron $($events4769.Count) eventos 4769" "SUCCESS"
        
        foreach ($event in $events4769) {
            $parsed = Parse-Event4769 -Event $event
            
            if ($parsed) {
                $suspiciousServiceTickets += $parsed
            }
        }
    } else {
        Write-Log "No se encontraron eventos 4769" "WARN"
    }
    
    Write-Log ""
    
    # ========================================================================
    # BUSCAR EVENT ID 4776 (NTLM Logon)
    # ========================================================================
    
    Write-Log "Buscando Event ID 4776 (NTLM Logon)..." "INFO"
    
    $events4776 = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4776
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $ntlmAttempts = @()
    
    if ($events4776) {
        Write-Log "Se encontraron $($events4776.Count) eventos 4776" "SUCCESS"
        
        foreach ($event in $events4776) {
            $parsed = Parse-Event4776 -Event $event
            
            if ($parsed) {
                $ntlmAttempts += $parsed
            }
        }
    } else {
        Write-Log "No se encontraron eventos 4776" "WARN"
    }
    
    Write-Log ""
    
    # ========================================================================
    # ANÁLISIS
    # ========================================================================
    
    Write-Log "Analizando patrones de Golden Ticket..." "INFO"
    Write-Log ""
    
    $goldenTicketIndicators = @()
    
    # Indicador 1: Múltiples TGT a krbtgt
    if ($suspiciousTGT.Count -gt 5) {
        Write-Log "🔴 [ALERTA] Múltiples solicitudes TGT a krbtgt detectadas" "ALERT"
        Write-Log "   Total: $($suspiciousTGT.Count) solicitudes en $HoursBack horas" "ALERT"
        
        $groupedByUser = $suspiciousTGT | Group-Object -Property User
        foreach ($group in $groupedByUser) {
            Write-Log "   Usuario: $($group.Name) - $($group.Count) solicitudes" "ALERT"
        }
        
        $goldenTicketIndicators += "Multiple TGT Requests"
        Write-Log ""
    }
    
    # Indicador 2: Solicitudes de múltiples tickets de servicio
    if ($suspiciousServiceTickets.Count -gt 10) {
        Write-Log "⚠️  Múltiples solicitudes de Service Tickets detectadas" "WARN"
        Write-Log "   Total: $($suspiciousServiceTickets.Count) solicitudes" "WARN"
        
        $servicesByName = $suspiciousServiceTickets | Group-Object -Property ServiceName
        Write-Log "   Servicios solicitados: $($servicesByName.Count)" "WARN"
        
        $goldenTicketIndicators += "Multiple Service Tickets"
        Write-Log ""
    }
    
    # Indicador 3: NTLM después de Kerberos
    if ($ntlmAttempts.Count -gt 0 -and $suspiciousTGT.Count -gt 0) {
        Write-Log "⚠️  Combinación de Kerberos + NTLM detectada" "WARN"
        Write-Log "   Esto podría indicar Golden Ticket + fallback a NTLM" "WARN"
        $goldenTicketIndicators += "Kerberos+NTLM Combination"
        Write-Log ""
    }
    
    # ========================================================================
    # RESUMEN FINAL
    # ========================================================================
    
    Write-Log "========================================" "INFO"
    Write-Log "RESUMEN" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    if ($goldenTicketIndicators.Count -gt 0) {
        Write-Log "🔴 INDICADORES DE GOLDEN TICKET DETECTADOS" "ALERT"
        Write-Log "   Total de indicadores: $($goldenTicketIndicators.Count)" "ALERT"
        Write-Log "   Indicadores encontrados:" "ALERT"
        foreach ($indicator in $goldenTicketIndicators) {
            Write-Log "     - $indicator" "ALERT"
        }
        Write-Log "   ACCIÓN RECOMENDADA: Investigar inmediatamente" "ALERT"
    } else {
        Write-Log "✓ No se detectaron indicadores de Golden Ticket" "SUCCESS"
    }
    
    Write-Log ""
    Write-Log "Estadísticas:" "INFO"
    Write-Log "  - Event 4768 (TGT): $($events4768.Count) eventos" "INFO"
    Write-Log "  - Event 4769 (Service): $($events4769.Count) eventos" "INFO"
    Write-Log "  - Event 4776 (NTLM): $($events4776.Count) eventos" "INFO"
    Write-Log ""
    Write-Log "========================================" "INFO"
    Write-Log "Análisis completado - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "========================================" "INFO"
    
    # Guardar reporte
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputPath "GoldenTicket_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    
    if ($suspiciousTGT.Count -gt 0) {
        $suspiciousTGT | Export-Csv -Path $reportFile -NoTypeInformation
        Write-Log "Reporte guardado en: $reportFile" "SUCCESS"
    }
    
    Write-Log ""
    
    return @{
        TGTRequests        = $suspiciousTGT
        ServiceTickets     = $suspiciousServiceTickets
        NTLMAttempts       = $ntlmAttempts
        Indicators         = $goldenTicketIndicators
    }
}

# Ejecutar
Main
