# Synthetic regression test: checks suppression is narrow, not account-wide.
[CmdletBinding()]
param()
$lab = $PSScriptRoot
$original = @(Import-Csv (Join-Path $lab 'sample-events-v3.csv'))
$otherCommand = 'Write-Output "Unexpected administrative command"'
$otherEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($otherCommand))
$testEvent = [pscustomobject]@{
    Timestamp='2026-10-20T09:26:00Z'; Host='LAB-IT01'; User='itadmin'
    ProcessName='powershell.exe'; CommandLine="powershell.exe -EncodedCommand $otherEncoded"
}
$testInput = Join-Path $lab 'sample-events-v3-regression.csv'
$testAlerts = Join-Path $lab 'alerts-v3-regression.csv'
$testAudit = Join-Path $lab 'approved-v3-regression.csv'
@($original) + @($testEvent) | Export-Csv -LiteralPath $testInput -NoTypeInformation
& (Join-Path $lab 'Detect-SuspiciousPowerShell-V3.ps1') -InputPath $testInput -OutputPath $testAlerts -AuditPath $testAudit
$alerts = @(Import-Csv -LiteralPath $testAlerts)
$approved = @(Import-Csv -LiteralPath $testAudit)
$checks = [ordered]@{
    'Five alerts remain (four original plus new suspicious test)' = ($alerts.Count -eq 5)
    'Exactly one approved event is audited' = ($approved.Count -eq 1)
    'Approved maintenance event not in alerts' = (@($alerts | Where-Object { $_.Host -eq 'LAB-IT01' -and $_.DecodedText -eq 'Write-Output "Routine IT maintenance"' }).Count -eq 0)
    'Different command from same admin still alerts' = (@($alerts | Where-Object { $_.Host -eq 'LAB-IT01' -and $_.User -eq 'itadmin' -and $_.DecodedText -eq $otherCommand }).Count -eq 1)
    'Original high-severity event still alerts' = (@($alerts | Where-Object { $_.Host -eq 'LAB-WS07' -and $_.Severity -eq 'High' }).Count -eq 1)
}
$failures = 0
foreach ($name in $checks.Keys) {
    if ($checks[$name]) { Write-Host "PASS: $name" }
    else { Write-Host "FAIL: $name"; $failures++ }
}
if ($failures -gt 0) { throw "$failures test(s) failed" }
Write-Host 'All five Version 3.1 checks passed.'
