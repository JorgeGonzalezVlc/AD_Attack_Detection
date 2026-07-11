#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AD-ThreatDetector.ps1
    Script unificado de detección de ataques en Active Directory
    
.DESCRIPTION
    Detecta indicadores de compromiso para los siguientes ataques:
    - 01: AS-REProasting (Event ID 4768, sin preauth)
    - 02: Kerberoasting (Event ID 4769, SPN)
    - 03: GPP Passwords (Event ID 5145, acceso a SYSVOL)
    - 04: GPO Permissions (Event ID 4697, tareas maliciosas)
    
.PARAMETER Domain
    Dominio a auditar (default: dominio local)
    
.PARAMETER OutputPath
    Ruta donde guardar el reporte HTML (default: C:\Reports\)
    
.PARAMETER HoursBack
    Número de horas hacia atrás para buscar eventos (default: 24)
    
.PARAMETER SMTPServer
    Servidor SMTP para enviar reporte por email (opcional)
    
.PARAMETER EmailTo
    Destinatario del reporte (opcional)

.EXAMPLE
    .\AD-ThreatDetector.ps1 -Domain "adlab.local" -HoursBack 24 -SMTPServer "mail.adlab.local" -EmailTo "admin@adlab.local"
#>

param(
    [string]$Domain = (Get-ADDomain).DNSRoot,
    [string]$OutputPath = "C:\Reports",
    [int]$HoursBack = 24,
    [string]$SMTPServer = "",
    [string]$EmailTo = ""
)

# ============================================================================
# CONFIGURACIÓN Y VARIABLES GLOBALES
# ============================================================================

$ScriptVersion = "1.0"
$ScriptName = "AD-ThreatDetector"
$ReportDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = Join-Path $OutputPath "AD_Threats_$ReportDate.html"
$LogFile = Join-Path $OutputPath "AD_Threats_$ReportDate.log"

$ThreatsFound = @()
$WarningsFound = @()
$InfoFound = @()

# Crear carpeta de reports si no existe
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    Add-Content -Path $LogFile -Value $LogMessage
    
    $Colors = @{
        "INFO"    = "White"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
    }
    
    Write-Host $LogMessage -ForegroundColor $Colors[$Level]
}

function Get-EventsWithinHours {
    param(
        [int]$EventID,
        [string]$LogName = "Security",
        [int]$Hours = $HoursBack
    )
    
    $StartTime = (Get-Date).AddHours(-$Hours)
    
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            ID        = $EventID
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
        
        return $events
    } catch {
        Write-Log "Error obteniendo eventos $EventID: $_" "ERROR"
        return $null
    }
}

function Add-Threat {
    param(
        [string]$AttackType,
        [string]$Description,
        [string]$Evidence,
        [int]$Severity = 3,
        [string]$Source = "Unknown"
    )
    
    $threat = [PSCustomObject]@{
        Timestamp      = Get-Date
        AttackType     = $AttackType
        Description    = $Description
        Evidence       = $Evidence
        Severity       = $Severity  # 1=Crítica, 2=Alta, 3=Media, 4=Baja
        Source         = $Source
        RecommendedAction = ""
    }
    
    $ThreatsFound += $threat
    
    $SeverityText = @{1 = "CRÍTICA"; 2 = "ALTA"; 3 = "MEDIA"; 4 = "BAJA"}[@($Severity)]
    Write-Log "⚠️  AMENAZA DETECTADA [$SeverityText]: $AttackType - $Description" "WARN"
}

function Add-Warning {
    param(
        [string]$Title,
        [string]$Description
    )
    
    $warning = [PSCustomObject]@{
        Timestamp   = Get-Date
        Title       = $Title
        Description = $Description
    }
    
    $WarningsFound += $warning
    Write-Log "⚠️  ADVERTENCIA: $Title" "WARN"
}

function Add-Info {
    param(
        [string]$Title,
        [string]$Description
    )
    
    $info = [PSCustomObject]@{
        Timestamp   = Get-Date
        Title       = $Title
        Description = $Description
    }
    
    $InfoFound += $info
    Write-Log "ℹ️  INFO: $Title" "INFO"
}

# ============================================================================
# DETECTOR 01: AS-REProasting (Event ID 4768, sin preauth)
# ============================================================================

function Detect-ASREProasting {
    Write-Log "Buscando indicadores de AS-REProasting..." "INFO"
    
    # Event ID 4768: Kerberos authentication ticket (TGT) was requested
    # Pre-auth = 0 indica AS-REProasting
    $events = Get-EventsWithinHours -EventID 4768
    
    if ($events) {
        foreach ($event in $events) {
            $eventData = $event.Properties
            
            # Intentar extraer información
            $userName = $eventData[0].Value
            $clientAddress = $eventData[4].Value
            $status = $eventData[7].Value
            
            # Si el status es 0, significa éxito sin preauth
            if ($status -eq "0x0") {
                Add-Threat -AttackType "AS-REProasting" `
                    -Description "Solicitud de TGT sin pre-autenticación para usuario: $userName" `
                    -Evidence "Event ID 4768 desde $clientAddress" `
                    -Severity 2 `
                    -Source "Event ID 4768"
            }
        }
    } else {
        Add-Info "AS-REProasting" "No se detectaron eventos de solicitud de TGT sin pre-autenticación en las últimas $HoursBack horas"
    }
}

# ============================================================================
# DETECTOR 02: Kerberoasting (Event ID 4769, SPN requests)
# ============================================================================

function Detect-Kerberoasting {
    Write-Log "Buscando indicadores de Kerberoasting..." "INFO"
    
    # Event ID 4769: Kerberos service ticket (TGS) was requested
    # Muchas solicitudes de TGS para SPNs específicos = Kerberoasting
    $events = Get-EventsWithinHours -EventID 4769
    
    if ($events) {
        # Agrupar por usuario solicitante
        $spnRequests = $events | Group-Object -Property @{e={$_.Properties[0].Value}} | 
                       Where-Object {$_.Count -gt 5}  # Más de 5 TGS en 24h es sospechoso
        
        foreach ($request in $spnRequests) {
            Add-Threat -AttackType "Kerberoasting" `
                -Description "Usuario $($request.Name) solicitó múltiples tickets de servicio ($($request.Count) solicitudes)" `
                -Evidence "Event ID 4769 x$($request.Count)" `
                -Severity 2 `
                -Source "Event ID 4769"
        }
    } else {
        Add-Info "Kerberoasting" "No se detectaron patrones de Kerberoasting en las últimas $HoursBack horas"
    }
}

# ============================================================================
# DETECTOR 03: GPP Passwords (Event ID 5145, acceso a SYSVOL)
# ============================================================================

function Detect-GPPPasswords {
    Write-Log "Buscando indicadores de GPP Password Extraction..." "INFO"
    
    # Event ID 5145: Network share object was accessed
    # Buscar acceso a SYSVOL buscando Groups.xml o similares
    $events = Get-EventsWithinHours -EventID 5145
    
    if ($events) {
        $suspiciousAccess = $events | Where-Object {
            $_.Properties[2].Value -match "Groups\.xml|.*\.xml" -and
            $_.Properties[2].Value -match "SYSVOL|Policies"
        }
        
        foreach ($access in $suspiciousAccess) {
            $sharePath = $access.Properties[2].Value
            $sourceIP = $access.Properties[5].Value
            $userName = $access.Properties[1].Value
            
            Add-Threat -AttackType "GPP Password Extraction" `
                -Description "Usuario $userName accedió a archivo de configuración: $sharePath desde $sourceIP" `
                -Evidence "Event ID 5145" `
                -Severity 2 `
                -Source "Event ID 5145"
        }
    } else {
        Add-Info "GPP Passwords" "No se detectó acceso sospechoso a SYSVOL en las últimas $HoursBack horas"
    }
}

# ============================================================================
# DETECTOR 04: GPO Abuse (Event ID 4697 + 5145, tareas maliciosas)
# ============================================================================

function Detect-GPOAbuse {
    Write-Log "Buscando indicadores de abuso de GPO..." "INFO"
    
    # Event ID 4697: Se creó una tarea programada
    $taskEvents = Get-EventsWithinHours -EventID 4697
    
    $suspiciousTasks = @()
    
    if ($taskEvents) {
        foreach ($event in $taskEvents) {
            $taskName = $event.Properties[0].Value
            $creator = $event.Properties[1].Value
            $taskCommand = $event.Properties[2].Value
            
            # Detectar comandos sospechosos
            if ($taskCommand -match "powershell|cmd\.exe|iex|downloadstring|system32\\regsvcs|certutil") {
                Add-Threat -AttackType "GPO Abuse - Malicious Scheduled Task" `
                    -Description "Tarea sospechosa creada: $taskName por $creator. Comando: $taskCommand" `
                    -Evidence "Event ID 4697" `
                    -Severity 1 `
                    -Source "Event ID 4697"
                
                $suspiciousTasks += $taskName
            }
        }
    }
    
    # Buscar también tareas en SYSVOL
    Write-Log "Buscando tareas maliciosas en SYSVOL..." "INFO"
    $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
    
    if (Test-Path $sysvolPath) {
        $taskXmls = Get-ChildItem -Path $sysvolPath -Recurse -Filter "ScheduledTasks.xml" -ErrorAction SilentlyContinue
        
        foreach ($xmlFile in $taskXmls) {
            try {
                [xml]$taskXml = Get-Content $xmlFile.FullName -ErrorAction SilentlyContinue
                $tasks = $taskXml.ScheduledTasks.Task
                
                if ($tasks) {
                    foreach ($task in $tasks) {
                        $command = $task.Properties.Command
                        
                        if ($command -match "powershell|cmd\.exe|iex|downloadstring|certutil|regsvcs") {
                            Add-Threat -AttackType "GPO Abuse - Malicious Task in SYSVOL" `
                                -Description "Tarea maliciosa en SYSVOL: $($xmlFile.FullName)" `
                                -Evidence "Comando: $command" `
                                -Severity 1 `
                                -Source "SYSVOL ScheduledTasks.xml"
                        }
                    }
                }
            } catch {
                Write-Log "Error parsing $($xmlFile.FullName): $_" "WARN"
            }
        }
    } else {
        Write-Log "SYSVOL no accesible o no existe: $sysvolPath" "WARN"
    }
    
    if (-not $taskEvents -and -not $suspiciousTasks) {
        Add-Info "GPO Abuse" "No se detectaron tareas programadas maliciosas en las últimas $HoursBack horas"
    }
}

# ============================================================================
# DETECTOR ADICIONAL: GPO Permissions (delegación sospechosa)
# ============================================================================

function Detect-GPOPermissions {
    Write-Log "Buscando delegación sospechosa en GPOs..." "INFO"
    
    try {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        
        $gpos = Get-GPO -All -Domain $Domain -ErrorAction SilentlyContinue
        
        foreach ($gpo in $gpos) {
            try {
                $acl = Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -ErrorAction SilentlyContinue
                
                foreach ($ace in $acl) {
                    # Detectar usuarios (no grupos) con permiso de "Editar configuración"
                    if ($ace.Permission -eq "Edit" -and $ace.Trustee.SidType -eq "User") {
                        Add-Warning -Title "GPO Delegación a Usuario" `
                            -Description "Usuario '$($ace.Trustee.Name)' tiene permiso EDITAR sobre GPO '$($gpo.DisplayName)' - Revisar si es intencional"
                    }
                }
            } catch {
                # Silenciosamente continuar
            }
        }
    } catch {
        Write-Log "No se pudo analizar GPOs: $_" "WARN"
    }
}

# ============================================================================
# GENERACIÓN DEL REPORTE HTML
# ============================================================================

function Generate-HTMLReport {
    $htmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Threat Detection Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e1e 0%, #2d2d2d 100%);
            color: #333;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #c41e3a 0%, #dc143c 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .meta {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 20px;
            padding: 30px;
            background: #f5f5f5;
            border-bottom: 3px solid #c41e3a;
        }
        .meta-item { text-align: center; }
        .meta-item .value { font-size: 2.5em; font-weight: bold; color: #c41e3a; }
        .meta-item .label { font-size: 0.9em; color: #666; margin-top: 5px; }
        .content { padding: 40px; }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            font-size: 1.8em;
            color: #c41e3a;
            border-bottom: 3px solid #c41e3a;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .threat-item {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
            page-break-inside: avoid;
        }
        .threat-item.critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        .threat-item.high {
            background: #fff3cd;
            border-left-color: #ffc107;
        }
        .threat-item.medium {
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }
        .threat-item.low {
            background: #d4edda;
            border-left-color: #28a745;
        }
        .threat-title {
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .threat-desc { margin: 10px 0; }
        .threat-evidence {
            font-size: 0.9em;
            color: #666;
            font-style: italic;
            margin-top: 10px;
        }
        .threat-severity {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin-top: 10px;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #ffc107; color: black; }
        .severity-medium { background: #17a2b8; color: white; }
        .severity-low { background: #28a745; color: white; }
        .warning-item {
            background: #e7f3ff;
            border-left: 5px solid #2196F3;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .info-item {
            background: #f0f0f0;
            border-left: 5px solid #666;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .no-threats {
            background: #d4edda;
            border: 2px solid #28a745;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
            color: #155724;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #c41e3a;
            color: white;
            font-weight: bold;
        }
        tr:hover { background: #f5f5f5; }
        .footer {
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            border-top: 3px solid #c41e3a;
            color: #666;
            font-size: 0.9em;
        }
        .recommendation {
            background: #e8f4f8;
            border-left: 5px solid #0c5460;
            padding: 15px;
            margin-top: 15px;
            border-radius: 3px;
            font-size: 0.95em;
        }
        .recommendation strong { color: #0c5460; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AD Threat Detection Report</h1>
            <p>Active Directory Security Analysis</p>
        </div>
        
        <div class="meta">
            <div class="meta-item">
                <div class="value">$($ThreatsFound.Count)</div>
                <div class="label">Amenazas Detectadas</div>
            </div>
            <div class="meta-item">
                <div class="value">$($WarningsFound.Count)</div>
                <div class="label">Advertencias</div>
            </div>
            <div class="meta-item">
                <div class="value">$($(Get-Date -Format 'yyyy-MM-dd HH:mm'))</div>
                <div class="label">Fecha del Reporte</div>
            </div>
            <div class="meta-item">
                <div class="value">$Domain</div>
                <div class="label">Dominio Auditado</div>
            </div>
        </div>
        
        <div class="content">
"@

    # Sección de amenazas
    if ($ThreatsFound.Count -gt 0) {
        $htmlContent += "<div class='section'><h2>⚠️ Amenazas Detectadas ($($ThreatsFound.Count))</h2>"
        
        foreach ($threat in $ThreatsFound | Sort-Object -Property Severity) {
            $severityClass = @{1 = "critical"; 2 = "high"; 3 = "medium"; 4 = "low"}[$threat.Severity]
            $severityText = @{1 = "CRÍTICA"; 2 = "ALTA"; 3 = "MEDIA"; 4 = "BAJA"}[$threat.Severity]
            
            $htmlContent += @"
            <div class="threat-item $severityClass">
                <div class="threat-title">🔴 $($threat.AttackType)</div>
                <div class="threat-desc"><strong>Descripción:</strong> $($threat.Description)</div>
                <div class="threat-evidence"><strong>Evidencia:</strong> $($threat.Evidence)</div>
                <div class="threat-severity severity-$severityClass">Severidad: $severityText</div>
                <div class="threat-desc"><strong>Fuente:</strong> $($threat.Source)</div>
            </div>
"@
        }
        
        $htmlContent += "</div>"
    } else {
        $htmlContent += "<div class='section'><h2>✅ Resumen de Amenazas</h2><div class='no-threats'>✓ No se detectaron amenazas en las últimas $HoursBack horas</div></div>"
    }
    
    # Sección de advertencias
    if ($WarningsFound.Count -gt 0) {
        $htmlContent += "<div class='section'><h2>⚠️ Advertencias ($($WarningsFound.Count))</h2>"
        
        foreach ($warning in $WarningsFound) {
            $htmlContent += @"
            <div class="warning-item">
                <strong>$($warning.Title)</strong><br>
                $($warning.Description)
            </div>
"@
        }
        
        $htmlContent += "</div>"
    }
    
    # Sección de info
    if ($InfoFound.Count -gt 0) {
        $htmlContent += "<div class='section'><h2>ℹ️ Información ($($InfoFound.Count))</h2>"
        
        foreach ($info in $InfoFound) {
            $htmlContent += @"
            <div class="info-item">
                <strong>$($info.Title)</strong><br>
                $($info.Description)
            </div>
"@
        }
        
        $htmlContent += "</div>"
    }
    
    # Recomendaciones generales
    $htmlContent += @"
        <div class="section">
            <h2>📋 Recomendaciones Generales</h2>
            <div class="recommendation">
                <strong>1. Auditoría:</strong> Asegurar que la auditoría de eventos de seguridad está activada en todos los DCs
            </div>
            <div class="recommendation">
                <strong>2. Delegación GPO:</strong> Revisar permisos de delegación en Group Policy Objects críticos
            </div>
            <div class="recommendation">
                <strong>3. SYSVOL:</strong> Monitorear cambios en SYSVOL regularmente para detectar inyecciones
            </div>
            <div class="recommendation">
                <strong>4. Logs:</strong> Centralizar y archivar logs en un SIEM para análisis a largo plazo
            </div>
            <div class="recommendation">
                <strong>5. Hardening:</strong> Implementar protecciones adicionales: MFA, PAWs, Tier 0 controls
            </div>
        </div>
        
        </div>
        
        <div class="footer">
            <p><strong>$ScriptName v$ScriptVersion</strong></p>
            <p>Generado: $(Get-Date -Format 'dddd, dd/MM/yyyy HH:mm:ss')</p>
            <p>Período auditado: Últimas $HoursBack horas</p>
            <p>Para más información, revisar: $LogFile</p>
        </div>
    </div>
</body>
</html>
"@

    return $htmlContent
}

# ============================================================================
# FUNCIÓN DE ENVÍO DE EMAIL
# ============================================================================

function Send-EmailReport {
    param(
        [string]$SMTPServer,
        [string]$To,
        [string]$ReportPath
    )
    
    if ([string]::IsNullOrEmpty($SMTPServer) -or [string]::IsNullOrEmpty($To)) {
        Write-Log "Email no configurado, saltando envío" "INFO"
        return
    }
    
    try {
        $subject = "[AD Threat Detection] Reporte - $ReportDate"
        $body = "Se ha generado un nuevo reporte de detección de amenazas en AD. Adjunto: $ReportPath"
        
        Send-MailMessage -SmtpServer $SMTPServer `
                        -From "ADMonitor@$Domain" `
                        -To $To `
                        -Subject $subject `
                        -Body $body `
                        -Attachments $ReportPath `
                        -ErrorAction Stop
        
        Write-Log "Reporte enviado a $To" "SUCCESS"
    } catch {
        Write-Log "Error enviando email: $_" "ERROR"
    }
}

# ============================================================================
# MAIN - EJECUCIÓN DEL SCRIPT
# ============================================================================

function Main {
    Write-Log "========================================" "INFO"
    Write-Log "$ScriptName v$ScriptVersion iniciado" "INFO"
    Write-Log "Dominio: $Domain | Período: $HoursBack horas" "INFO"
    Write-Log "========================================" "INFO"
    
    # Ejecutar detectores
    Detect-ASREProasting
    Detect-Kerberoasting
    Detect-GPPPasswords
    Detect-GPOAbuse
    Detect-GPOPermissions
    
    # Generar reporte HTML
    Write-Log "Generando reporte HTML..." "INFO"
    $htmlReport = Generate-HTMLReport
    $htmlReport | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Log "Reporte guardado en: $ReportFile" "SUCCESS"
    
    # Enviar email si está configurado
    if ($SMTPServer -and $EmailTo) {
        Send-EmailReport -SMTPServer $SMTPServer -To $EmailTo -ReportPath $ReportFile
    }
    
    # Resumen final
    Write-Log "========================================" "INFO"
    Write-Log "RESUMEN FINAL:" "INFO"
    Write-Log "  - Amenazas detectadas: $($ThreatsFound.Count)" "INFO"
    Write-Log "  - Advertencias: $($WarningsFound.Count)" "INFO"
    Write-Log "  - Información: $($InfoFound.Count)" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "$ScriptName finalizado" "SUCCESS"
    
    # Retornar objeto con resultados
    return [PSCustomObject]@{
        Threats   = $ThreatsFound
        Warnings  = $WarningsFound
        Info      = $InfoFound
        ReportPath = $ReportFile
        LogPath    = $LogFile
    }
}

# Ejecutar
Main
