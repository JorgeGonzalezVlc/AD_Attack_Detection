#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detect-DCSync.ps1
    Detecta intentos de ataque DCSync mediante Event ID 4662
    
.DESCRIPTION
    Monitorea Event ID 4662 (Directory Service Access) para detectar:
    - Usuarios normales intentando hacer DCSync
    - Acceso a domainDNS
    - Máscara de acceso 0x100 (replicación)
    
    DCSync permite extraer TODOS los hashes NTLM del dominio
    sin ser admin local del DC.

.PARAMETER HoursBack
    Número de horas hacia atrás a auditar (default: 24)
    
.PARAMETER OutputPath
    Ruta para guardar reporte (default: C:\Reports\)

.EXAMPLE
    .\Detect-DCSync.ps1 -HoursBack 24
    .\Detect-DCSync.ps1 -HoursBack 48 -OutputPath "C:\Security"
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

function Get-DCsFromDomain {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dcs = $domain.DomainControllers | ForEach-Object { $_.Name }
        return $dcs
    } catch {
        return @()
    }
}

function Parse-Event4662 {
    param([object]$Event)
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $data = @{
            TimeCreated   = $Event.TimeCreated
            User          = ($eventData | Where-Object {$_.Name -eq "SubjectUserName"}).InnerText
            Domain        = ($eventData | Where-Object {$_.Name -eq "SubjectDomainName"}).InnerText
            ObjectType    = ($eventData | Where-Object {$_.Name -eq "ObjectType"}).InnerText
            ObjectName    = ($eventData | Where-Object {$_.Name -eq "ObjectName"}).InnerText
            AccessMask    = ($eventData | Where-Object {$_.Name -eq "AccessMask"}).InnerText
            Properties    = ($eventData | Where-Object {$_.Name -eq "Properties"}).InnerText
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
    Write-Log "DCSync Attack Detector v1.0" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    Write-Log "Parámetros:" "INFO"
    Write-Log "  - Período: $HoursBack horas" "INFO"
    Write-Log "  - Rutas de salida: $OutputPath" "INFO"
    Write-Log ""
    
    $startTime = (Get-Date).AddHours(-$HoursBack)
    
    # ========================================================================
    # BUSCAR EVENT ID 4662 (Directory Service Access)
    # ========================================================================
    
    Write-Log "Buscando Event ID 4662 (Directory Service Access)..." "INFO"
    
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        ID        = 4662
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if (-not $events) {
        Write-Log "No se encontraron eventos 4662" "WARN"
        Write-Log ""
        return
    }
    
    Write-Log "Se encontraron $($events.Count) eventos 4662" "SUCCESS"
    Write-Log ""
    
    # ========================================================================
    # FILTRAR INTENTOS DE DCSYNC
    # ========================================================================
    
    Write-Log "Analizando eventos para detectar DCSync..." "INFO"
    
    $dcsyncAttempts = @()
    $suspiciousAccess = @()
    
    foreach ($event in $events) {
        $parsed = Parse-Event4662 -Event $event
        
        if ($parsed) {
            # Detectar DCSync específicamente
            # Características: acceso a domainDNS, máscara 0x100
            if ($parsed.ObjectType -match "domainDNS|CN=NTDS" -and $parsed.AccessMask -match "0x100") {
                $dcsyncAttempts += $parsed
            }
            
            # Detectar acceso anómalo a DS
            if ($parsed.ObjectType -match "domainDNS" -or $parsed.ObjectName -match "CN=Users|CN=Computers") {
                $suspiciousAccess += $parsed
            }
        }
    }
    
    Write-Log ""
    
    # ========================================================================
    # REPORTE DE DCSYNC
    # ========================================================================
    
    if ($dcsyncAttempts.Count -gt 0) {
        Write-Log "🔴 [CRÍTICA] INTENTOS DE DCSYNC DETECTADOS" "ALERT"
        Write-Log "   Total de intentos: $($dcsyncAttempts.Count)" "ALERT"
        Write-Log ""
        
        foreach ($attempt in $dcsyncAttempts | Sort-Object -Property TimeCreated -Descending) {
            Write-Log "   ════════════════════════════════════" "ALERT"
            Write-Log "   Hora: $($attempt.TimeCreated)" "ALERT"
            Write-Log "   Usuario: $($attempt.Domain)\$($attempt.User)" "ALERT"
            Write-Log "   Objeto: $($attempt.ObjectName)" "ALERT"
            Write-Log "   Tipo de objeto: $($attempt.ObjectType)" "ALERT"
            Write-Log "   Máscara de acceso: $($attempt.AccessMask)" "ALERT"
            Write-Log ""
        }
    } else {
        Write-Log "✓ No se detectaron intentos de DCSync" "SUCCESS"
    }
    
    Write-Log ""
    
    # ========================================================================
    # REPORTE DE ACCESO ANÓMALO A DS
    # ========================================================================
    
    if ($suspiciousAccess.Count -gt 0) {
        Write-Log "⚠️  ACCESO ANÓMALO A DIRECTORIO SERVICES" "WARN"
        Write-Log "   Total de accesos: $($suspiciousAccess.Count)" "WARN"
        Write-Log ""
        
        $groupedByUser = $suspiciousAccess | Group-Object -Property User
        
        foreach ($group in $groupedByUser | Sort-Object -Property Count -Descending | Select-Object -First 10) {
            Write-Log "   Usuario: $($group.Name) - $($group.Count) accesos" "WARN"
        }
        
        Write-Log ""
    } else {
        Write-Log "✓ No se detectó acceso anómalo a Directory Services" "SUCCESS"
    }
    
    Write-Log ""
    
    # ========================================================================
    # RESUMEN
    # ========================================================================
    
    Write-Log "========================================" "INFO"
    Write-Log "RESUMEN" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log ""
    
    if ($dcsyncAttempts.Count -gt 0) {
        Write-Log "🔴 AMENAZA DETECTADA" "ALERT"
        Write-Log "   - $($dcsyncAttempts.Count) intentos de DCSync" "ALERT"
        Write-Log "   - Usuarios normales intentando extraer hashes NTLM" "ALERT"
        Write-Log "   - ACCIÓN RECOMENDADA: Investigar inmediatamente" "ALERT"
        Write-Log "   - Verificar si usuarios tienen permisos de replicación legítimos" "ALERT"
    } else {
        Write-Log "✓ No se detectaron intentos de DCSync" "SUCCESS"
    }
    
    if ($suspiciousAccess.Count -gt 10) {
        Write-Log "⚠️  VOLUMEN ANÓMALO DE ACCESO A DS" "WARN"
        Write-Log "   - Revisar usuarios con acceso frecuente a Directory Services" "WARN"
    } else {
        Write-Log "✓ Acceso a DS dentro de los parámetros normales" "SUCCESS"
    }
    
    Write-Log ""
    Write-Log "========================================" "INFO"
    Write-Log "Análisis completado - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "========================================" "INFO"
    
    # Guardar reporte
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputPath "DCSync_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    
    if ($dcsyncAttempts.Count -gt 0) {
        $dcsyncAttempts | Export-Csv -Path $reportFile -NoTypeInformation
        Write-Log "Reporte DCSync guardado en: $reportFile" "SUCCESS"
    }
    
    $suspiciousFile = Join-Path $OutputPath "DSAccess_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    if ($suspiciousAccess.Count -gt 0) {
        $suspiciousAccess | Export-Csv -Path $suspiciousFile -NoTypeInformation
        Write-Log "Reporte de acceso DS guardado en: $suspiciousFile" "SUCCESS"
    }
    
    Write-Log ""
    
    return @{
        DCsyncAttempts  = $dcsyncAttempts
        SuspiciousAccess = $suspiciousAccess
    }
}

# Ejecutar
Main
