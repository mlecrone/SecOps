# Portfolio lab v3.1: synthetic telemetry only. Never executes decoded content.
[CmdletBinding()]
param([string]$InputPath, [string]$OutputPath, [string]$AuditPath)

if ([string]::IsNullOrWhiteSpace($InputPath)) { $InputPath = Join-Path $PSScriptRoot 'sample-events-v3.csv' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $PSScriptRoot 'alerts-v3-tuned.csv' }
if ([string]::IsNullOrWhiteSpace($AuditPath)) { $AuditPath = Join-Path $PSScriptRoot 'approved-activity.csv' }
if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw "Input CSV not found: $InputPath" }
$events = @(Import-Csv -LiteralPath $InputPath)
$required = @('Timestamp','Host','User','ProcessName','CommandLine')
if ($events.Count -gt 0) {
    foreach ($column in $required) {
        if (-not $events[0].PSObject.Properties[$column]) { throw "Missing CSV column: $column" }
    }
}
$encodedPattern = '(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?:\s+|:)(?<payload>\S+)'
$bypassPattern = '(?i)(?:^|\s)-(?:executionpolicy|ep)\s+bypass(?=\s|$)'
$approvedText = 'Write-Output "Routine IT maintenance"'
$alerts = [System.Collections.Generic.List[object]]::new()
$approved = [System.Collections.Generic.List[object]]::new()
foreach ($event in $events) {
    $process = [string]$event.ProcessName
    $command = [string]$event.CommandLine
    if ($process -notmatch '(?i)^(?:powershell|pwsh)\.exe$') { continue }
    $encodedMatch = [regex]::Match($command, $encodedPattern)
    $encoded = $encodedMatch.Success
    $bypass = [regex]::IsMatch($command, $bypassPattern)
    if (-not ($encoded -or $bypass)) { continue }
    $decoded = ''
    $decodeStatus = 'Not applicable'
    if ($encoded) {
        $payload = $encodedMatch.Groups['payload'].Value
        if ($payload.Length -gt 8192) {
            $decodeStatus = 'Skipped: payload exceeds lab limit'
        } else {
            try {
                $bytes = [Convert]::FromBase64String($payload)
                if (($bytes.Length % 2) -ne 0) { throw 'Invalid UTF-16LE byte length' }
                $decoded = [Text.Encoding]::Unicode.GetString($bytes)
                $decodeStatus = 'Decoded for inspection only'
            } catch {
                $decodeStatus = 'Invalid Base64 or UTF-16LE payload'
            }
        }
    }
    # Teaching-only allowlist: exact account, host, process, decoded text, and no bypass.
    # This is not strong enough for production authorization or attacker-resistant tuning.
    $isApproved = ($event.Host -ceq 'LAB-IT01' -and
                   $event.User -ceq 'itadmin' -and
                   $process -ceq 'powershell.exe' -and
                   $encoded -and -not $bypass -and
                   $decodeStatus -eq 'Decoded for inspection only' -and
                   $decoded -ceq $approvedText)
    if ($isApproved) {
        $approved.Add([pscustomobject]@{
            Timestamp = $event.Timestamp; Host = $event.Host; User = $event.User
            ProcessName = $process; CommandLine = $command
            DecodedText = $decoded; Disposition = 'Approved lab activity - retained for audit'
        })
        continue
    }
    $reason = @()
    if ($encoded) { $reason += 'Encoded PowerShell command' }
    if ($bypass) { $reason += 'Execution policy bypass' }
    $severity = if ($encoded -and $bypass) { 'High' } else { 'Medium' }
    $nextStep = if ($severity -eq 'High') {
        'Prioritize review of user, parent process, script block logs and endpoint activity'
    } else {
        'Validate business purpose, parent process, user and surrounding endpoint activity'
    }
    $alerts.Add([pscustomobject]@{
        Timestamp = $event.Timestamp; Host = $event.Host; User = $event.User
        Severity = $severity; Reason = ($reason -join '; ')
        ProcessName = $process; CommandLine = $command
        DecodedText = $decoded; DecodeStatus = $decodeStatus
        InvestigationGuidance = $nextStep
    })
}
if ($alerts.Count -gt 0) { $alerts | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 }
elseif (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath }
if ($approved.Count -gt 0) { $approved | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8 }
elseif (Test-Path -LiteralPath $AuditPath) { Remove-Item -LiteralPath $AuditPath }
Write-Host "Events analyzed: $($events.Count)"
Write-Host "Alerts generated: $($alerts.Count)"
Write-Host "Approved activity retained: $($approved.Count)"
Write-Host "High: $(@($alerts | Where-Object Severity -eq 'High').Count); Medium: $(@($alerts | Where-Object Severity -eq 'Medium').Count)"
if ($alerts.Count -gt 0) { Write-Host "Alert report: $OutputPath" }
if ($approved.Count -gt 0) { Write-Host "Approved activity report: $AuditPath" }
