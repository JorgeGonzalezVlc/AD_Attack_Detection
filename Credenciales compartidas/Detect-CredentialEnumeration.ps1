#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect-CredentialEnumeration.ps1
    Detecta enumeración de credenciales en compartidas SMB (Event ID 5145)
    
.DESCRIPTION
    Analiza Event ID 5145 para detectar patrones de acceso rápido a archivos
    de configuración que podrían indicar búsqueda de credenciales.
    
    Lógica de alertas:
    - 1 acceso: Normal (sin alerta)
    - 5+ accesos en <1 min: ALERTA MEDIA
    - 20+ accesos en <3 min: ALERTA GRAVE

.PARAMETER HoursBack
    Número de horas hacia atrás a auditar (default: 24)
    
.PARAMETER OutputPath
    Ruta para guardar reporte (default: C:\Reports\)

.EXAMPLE
    .\Detect-CredentialEnumeration.ps1 -HoursBack 24 -Verbose
#>

param(
    [int]$HoursBack = 24,
    [string]$OutputPath = "C:\Reports",
    [int]$AlertMediaThreshold = 5,      # 5+ accesos en <1 minuto
    [int]$AlertGraveThreshold = 20,     # 20+ accesos en <3 minutos
    [string]$SuspiciousFileTypes = "ps1|bat|cmd|ini|config|xml|conf|txt"
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# FUNCIONES
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    $Colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "DEBUG"   = "Gray"
    }
    
    Write-Host $LogMessage -ForegroundColor $Colors[$Level]
}

function Get-SecurityEvents5145 {
    param(
        [int]$Hours
    )
    
    $startTime = (Get-Date).AddHours(-$Hours)
    
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            ID        = 5145
            StartTime = $startTime
        } -ErrorAction Stop
        
        return $events
    } catch {
        Write-Log "Error obteniendo eventos 5145: $_" "ERROR"
        return $null
    }
}

function Parse-Event5145 {
    param(
        [object]$Event
    )
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated = $Event.TimeCreated
            User        = ($eventData | Where-Object {$_.Name -eq "SubjectUserName"}).InnerText
            Domain      = ($eventData | Where-Object {$_.Name -eq "SubjectDomainName"}).InnerText
            File        = ($eventData | Where-Object {$_.Name -eq "RelativeTargetName"}).InnerText
            Share       = ($eventData | Where-Object {$_.Name -eq "ShareName"}).InnerText
            IP          = ($eventData | Where-Object {$_.Name -eq "SourceIPAddress"}).InnerText
            Access      = ($eventData | Where-Object {$_.Name -eq "AccessMask"}).InnerText
        }
        
        return $data
    } catch {
        return $null
    }
}

function Analyze-AccessPatterns {
    param(
        [object[]]$ParsedEvents,
        [int]$MediaThreshold,
        [int]$GraveThreshold
    )
    
    $alerts = @()
    $suspiciousUsers = @{}
    
    # Agrupar por usuario y dominio
    $groupedByUser = $ParsedEvents | Group-Object -Property @{e={"$($_.Domain)\$($_.User)"}}, Share
    
    foreach ($group in $groupedByUser) {
        $userShare = $group.Name
        $events = $group.Group | Sort-Object -Property TimeCreated
        
        if ($events.Count -lt 2) {
            continue
        }
        
        $userKey = $userShare
        
        # Analizar por ventanas de tiempo
        for ($i = 0; $i -lt $events.Count; $i++) {
            $currentEvent = $events[$i]
            $currentTime = $currentEvent.TimeCreated
            
            # Ventana de 1 minuto
            $oneMinEvents = $events | Where-Object {
                $diff = [Math]::Abs(($_.TimeCreated - $currentTime).TotalSeconds)
                $diff -le 60
            }
            
            # Ventana de 3 minutos
            $threeMinEvents = $events | Where-Object {
                $diff = [Math]::Abs(($_.TimeCreated - $currentTime).TotalSeconds)
                $diff -le 180
            }
            
            # Verificar alertas
            if ($threeMinEvents.Count -ge $GraveThreshold) {
                $alert = [PSCustomObject]@{
                    Severity      = "GRAVE"
                    User          = $currentEvent.User
                    Domain        = $currentEvent.Domain
                    Share         = $currentEvent.Share
                    Count         = $threeMinEvents.Count
                    TimeWindow    = "3 minutos"
                    Files         = ($threeMinEvents.File | Sort-Object -Unique) -join ", "
                    FirstAccess   = ($threeMinEvents | Sort-Object -Property TimeCreated | Select-Object -First 1).TimeCreated
                    LastAccess    = ($threeMinEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1).TimeCreated
                    Details       = "Acceso rápido a múltiples archivos - POSIBLE ENUMERACIÓN DE CREDENCIALES"
                }
                
                $alerts += $alert
                
                # Registrar usuario sospechoso
                $suspiciousUsers[$userKey] = @{
                    Severity = "GRAVE"
                    Count    = $threeMinEvents.Count
                }
                
            } elseif ($oneMinEvents.Count -ge $MediaThreshold) {
                
                # Solo alertar si no hay alerta grave ya
                if (-not ($suspiciousUsers[$userKey] -and $suspiciousUsers[$userKey].Severity -eq "GRAVE")) {
                    $alert = [PSCustomObject]@{
                        Severity      = "MEDIA"
                        User          = $currentEvent.User
                        Domain        = $currentEvent.Domain
                        Share         = $currentEvent.Share
                        Count         = $oneMinEvents.Count
                        TimeWindow    = "1 minuto"
                        Files         = ($oneMinEvents.File | Sort-Object -Unique) -join ", "
                        FirstAccess   = ($oneMinEvents | Sort-Object -Property TimeCreated | Select-Object -First 1).TimeCreated
                        LastAccess    = ($oneMinEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1).TimeCreated
                        Details       = "Enumeración de archivos en ventana corta"
                    }
                    
                    $alerts += $alert
                    
                    if (-not $suspiciousUsers[$userKey]) {
                        $suspiciousUsers[$userKey] = @{
                            Severity = "MEDIA"
                            Count    = $oneMinEvents.Count
                        }
                    }
                }
            }
        }
    }
    
    # Eliminar duplicados (mantener solo la alerta más grave)
    $uniqueAlerts = $alerts | Group-Object -Property User, Domain, Share | ForEach-Object {
        $_.Group | Sort-Object -Property Severity -Descending | Select-Object -First 1
    }
    
    return @{
        Alerts = $uniqueAlerts
        SuspiciousUsers = $suspiciousUsers
    }
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    Write-Log "========================================" "INFO"
    Write-Log "Credential Enumeration Detector v1.0" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    Write-Log "Parámetros de detección:" "INFO"
    Write-Log "  - Período: $HoursBack horas" "INFO"
    Write-Log "  - Alerta MEDIA: $AlertMediaThreshold+ accesos en <1 min" "INFO"
    Write-Log "  - Alerta GRAVE: $AlertGraveThreshold+ accesos en <3 min" "INFO"
    Write-Log "  - Tipos sospechosos: $SuspiciousFileTypes" "INFO"
    Write-Log ""
    
    # Obtener eventos
    Write-Log "Buscando eventos Event ID 5145..." "INFO"
    $events = Get-SecurityEvents5145 -Hours $HoursBack
    
    if (-not $events) {
        Write-Log "No se encontraron eventos 5145" "WARN"
        return
    }
    
    Write-Log "Se encontraron $($events.Count) eventos 5145" "SUCCESS"
    Write-Log ""
    
    # Parsear eventos
    Write-Log "Parseando eventos..." "INFO"
    $parsedEvents = @()
    
    foreach ($event in $events) {
        $parsed = Parse-Event5145 -Event $event
        
        if ($parsed) {
            # Filtrar por tipos de archivo sospechosos
            if ($parsed.File -match $SuspiciousFileTypes) {
                $parsedEvents += $parsed
            }
        }
    }
    
    Write-Log "Se filtraron $($parsedEvents.Count) accesos a archivos sospechosos" "SUCCESS"
    Write-Log ""
    
    if ($parsedEvents.Count -eq 0) {
        Write-Log "No se detectaron patrones sospechosos" "INFO"
        return
    }
    
    # Analizar patrones
    Write-Log "Analizando patrones de acceso..." "INFO"
    $analysis = Analyze-AccessPatterns -ParsedEvents $parsedEvents -MediaThreshold $AlertMediaThreshold -GraveThreshold $AlertGraveThreshold
    
    Write-Log ""
    Write-Log "========================================" "INFO"
    Write-Log "RESULTADO DEL ANÁLISIS" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    if ($analysis.Alerts.Count -eq 0) {
        Write-Log "✓ No se detectaron patrones de enumeración" "SUCCESS"
    } else {
        Write-Log "⚠️  Se detectaron $($analysis.Alerts.Count) patrón(es) sospechoso(s)" "WARN"
        Write-Log ""
        
        foreach ($alert in $analysis.Alerts) {
            $icon = if ($alert.Severity -eq "GRAVE") { "🔴" } else { "⚠️" }
            Write-Log "$icon [$($alert.Severity)] $($alert.Domain)\$($alert.User) en $($alert.Share)" "WARN"
            Write-Log "    - Accesos: $($alert.Count) en $($alert.TimeWindow)" "WARN"
            Write-Log "    - Archivos: $($alert.Files.Substring(0, [Math]::Min(100, $alert.Files.Length)))" "WARN"
            Write-Log "    - Período: $($alert.FirstAccess) - $($alert.LastAccess)" "WARN"
            Write-Log "    - Detalles: $($alert.Details)" "WARN"
            Write-Log ""
        }
    }
    
    # Guardar reporte
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputPath "CredentialEnum_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    $analysis.Alerts | Export-Csv -Path $reportFile -NoTypeInformation
    
    Write-Log "Reporte guardado en: $reportFile" "SUCCESS"
    Write-Log ""
    Write-Log "========================================" "INFO"
    Write-Log "Análisis completado" "SUCCESS"
    Write-Log "========================================" "INFO"
    
    return $analysis.Alerts
}

# Ejecutar
Main
