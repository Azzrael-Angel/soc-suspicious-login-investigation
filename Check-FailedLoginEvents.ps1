# ========================================================================
# Script: Check Windows Failed Login Events
# Description: Retrieves and analyzes Windows failed login attempts
# Author: Security Admin
# Date: June 2026
# ========================================================================

# PART 1: SET EXECUTION POLICY (Run as Administrator)
# ========================================================================
# This ensures the script can run on the system
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# PART 2: DEFINE SCRIPT PARAMETERS
# ========================================================================
# Parameters allow customization when running the script
param (
    [int]$HoursBack = 24,                    # Look back this many hours (default: 24)
    [int]$MaxEvents = 100,                   # Maximum number of events to retrieve
    [string]$ComputerName = $env:COMPUTERNAME,  # Which computer to check (default: local)
    [switch]$ExportToCSV                     # Switch to export results to CSV
)

# PART 3: INITIALIZE VARIABLES
# ========================================================================
# Store configuration and helper variables
$ErrorActionPreference = "Continue"          # Continue on errors instead of stopping
$EventLogName = "Security"                   # Windows Security event log
$FailedLoginEventID = 4625                   # Event ID for failed login attempt
$StartTime = (Get-Date).AddHours(-$HoursBack)  # Calculate time range
$CSVPath = "C:\Logs\FailedLogins_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# PART 4: CREATE OUTPUT DIRECTORY IF NEEDED
# ========================================================================
if ($ExportToCSV -and -not (Test-Path "C:\Logs")) {
    New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null
    Write-Host "Created C:\Logs directory" -ForegroundColor Green
}

# PART 5: RETRIEVE FAILED LOGIN EVENTS
# ========================================================================
Write-Host "Retrieving failed login events from the last $HoursBack hours..." -ForegroundColor Cyan

try {
    # Query the Security event log for failed login attempts
    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName      = $EventLogName
        ID           = $FailedLoginEventID
        StartTime    = $StartTime
    } -ComputerName $ComputerName -MaxEvents $MaxEvents -ErrorAction Stop
    
    Write-Host "Found $($FailedLogins.Count) failed login event(s)" -ForegroundColor Green
}
catch {
    # Handle errors (e.g., no events found, access denied)
    Write-Host "Error retrieving events: $_" -ForegroundColor Red
    Write-Host "Make sure you're running as Administrator and have access to the Security log." -ForegroundColor Yellow
    exit
}

# PART 6: PARSE AND EXTRACT EVENT DATA
# ========================================================================
Write-Host "`nProcessing events..." -ForegroundColor Cyan

$ParsedEvents = foreach ($event in $FailedLogins) {
    # Parse the XML event data
    $eventXML = [xml]$event.ToXml()
    
    # Extract relevant fields from the event
    $eventData = @{
        TimeGenerated  = $event.TimeCreated                    # When the event occurred
        EventID        = $event.Id                             # Event ID (4625)
        ComputerName   = $event.MachineName                    # Which computer
        AccountName    = (
            $eventXML.Event.EventData.Data | 
            Where-Object {$_.Name -eq "TargetUserName"}
        ).'#text'                                              # User account that failed to login
        SourceIP       = (
            $eventXML.Event.EventData.Data | 
            Where-Object {$_.Name -eq "IpAddress"}
        ).'#text'                                              # IP address of failed attempt
        FailureCode    = (
            $eventXML.Event.EventData.Data | 
            Where-Object {$_.Name -eq "Status"}
        ).'#text'                                              # Failure reason code
        FailureReason  = ConvertFailureCode(
            (
                $eventXML.Event.EventData.Data | 
                Where-Object {$_.Name -eq "Status"}
            ).'#text'
        )                                                       # Human-readable failure reason
        LogonType      = (
            $eventXML.Event.EventData.Data | 
            Where-Object {$_.Name -eq "LogonType"}
        ).'#text'                                              # Type of logon attempted
        WorkstationName = (
            $eventXML.Event.EventData.Data | 
            Where-Object {$_.Name -eq "WorkstationName"}
        ).'#text'                                              # Source workstation
    }
    
    [PSCustomObject]$eventData
}

# PART 7: CONVERT FAILURE CODES TO READABLE TEXT
# ========================================================================
# Function to translate Windows failure codes into understandable messages
function ConvertFailureCode {
    param([string]$Code)
    
    $failureCodes = @{
        "0xC000005E" = "No logon servers available"
        "0xC000006A" = "Wrong password"
        "0xC000006D" = "Unknown user name or bad password"
        "0xC000006E" = "User logon with misspelled or bad user account"
        "0xC000006F" = "User logon outside authorized hours"
        "0xC0000070" = "User logon from unauthorized workstation"
        "0xC0000071" = "User logon with expired password"
        "0xC0000072" = "User logon to account disabled by administrator"
        "0xC000009A" = "Insufficient system resources"
        "0xC0000193" = "Account expired"
        "0xC0000224" = "User must change password at next logon"
        "0xC0000234" = "User account locked out"
    }
    
    return $failureCodes[$Code] -or "Unknown failure code: $Code"
}

# PART 8: DISPLAY RESULTS IN FORMATTED TABLE
# ========================================================================
if ($ParsedEvents.Count -gt 0) {
    Write-Host "`n=== FAILED LOGIN SUMMARY ===" -ForegroundColor Yellow
    Write-Host "Time Range: $(Get-Date $StartTime -Format 'yyyy-MM-dd HH:mm:ss') to $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    
    $ParsedEvents | Select-Object -Property TimeGenerated, AccountName, SourceIP, FailureReason, LogonType, WorkstationName | 
        Format-Table -AutoSize
}
else {
    Write-Host "No failed login events found in the specified time range." -ForegroundColor Green
}

# PART 9: GENERATE STATISTICS
# ========================================================================
Write-Host "`n=== STATISTICS ===" -ForegroundColor Yellow

# Most commonly targeted accounts
Write-Host "`nTop 5 Most Targeted Accounts:" -ForegroundColor Cyan
$ParsedEvents | Group-Object -Property AccountName -NoElement | 
    Sort-Object -Property Count -Descending | 
    Select-Object -First 5 | 
    Format-Table -AutoSize

# Most common failure reasons
Write-Host "Top 5 Most Common Failure Reasons:" -ForegroundColor Cyan
$ParsedEvents | Group-Object -Property FailureReason -NoElement | 
    Sort-Object -Property Count -Descending | 
    Select-Object -First 5 | 
    Format-Table -AutoSize

# Most frequently attacking IP addresses
Write-Host "Top 5 Most Frequent Source IPs:" -ForegroundColor Cyan
$ParsedEvents | Group-Object -Property SourceIP -NoElement | 
    Sort-Object -Property Count -Descending | 
    Select-Object -First 5 | 
    Format-Table -AutoSize

# PART 10: EXPORT TO CSV (Optional)
# ========================================================================
if ($ExportToCSV -and $ParsedEvents.Count -gt 0) {
    try {
        $ParsedEvents | Export-Csv -Path $CSVPath -NoTypeInformation -Force
        Write-Host "`n✓ Results exported to: $CSVPath" -ForegroundColor Green
    }
    catch {
        Write-Host "`n✗ Failed to export to CSV: $_" -ForegroundColor Red
    }
}

# PART 11: GENERATE SUMMARY REPORT
# ========================================================================
Write-Host "`n=== SUMMARY REPORT ===" -ForegroundColor Yellow
Write-Host "Total Failed Login Attempts: $($ParsedEvents.Count)" -ForegroundColor Cyan
Write-Host "Computer Scanned: $ComputerName" -ForegroundColor Cyan
Write-Host "Time Period Analyzed: Last $HoursBack hours" -ForegroundColor Cyan

if ($ParsedEvents.Count -gt 0) {
    $suspiciousIPs = $ParsedEvents | Group-Object -Property SourceIP | Where-Object {$_.Count -gt 5}
    if ($suspiciousIPs) {
        Write-Host "`n⚠ WARNING: Found suspicious activity from these IPs (>5 attempts):" -ForegroundColor Red
        $suspiciousIPs | ForEach-Object {
            Write-Host "  - $($_.Name): $($_.Count) attempts" -ForegroundColor Red
        }
    }
}

Write-Host "`nScript execution completed." -ForegroundColor Green
