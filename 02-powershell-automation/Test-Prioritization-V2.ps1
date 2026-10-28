# Regression tests; only synthetic CSV data is used.
[CmdletBinding()]
param()
$scriptPath = Join-Path $PSScriptRoot 'Prioritize-Vulnerabilities-V2.ps1'
$inputPath = Join-Path $PSScriptRoot 'sample-vulnerabilities-v2.csv'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('SecOps-V2-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$passed = 0; $failed = 0
function Check([bool]$Condition, [string]$Description) {
    if ($Condition) { $script:passed++; Write-Host "PASS: $Description" }
    else { $script:failed++; Write-Host "FAIL: $Description" }
}
try {
    $output = Join-Path $temp 'queue.csv'
    & $scriptPath -InputPath $inputPath -OutputPath $output
    $rows = @(Import-Csv $output)
    Check ($rows.Count -eq 8) 'All eight synthetic findings are retained'
    Check ((@($rows | Where-Object Priority -eq 'P1')).Count -eq 3) 'Three findings are P1'
    Check ((@($rows | Where-Object FindingId -eq 'V-007')[0].Priority) -eq 'P1') 'Confirmed active exploitation on internet-facing asset overrides score to P1'
    Check ((@($rows | Where-Object FindingId -eq 'V-005')[0].Priority) -eq 'P2') 'Known exploitation alone does not automatically override to P1'
    Check ((@($rows | Where-Object FindingId -eq 'V-008')[0].AnalystReview) -eq 'Yes') 'Active exploitation with unknown applicability requires analyst review'
    Check ((@($rows | Where-Object FindingId -eq 'V-003')[0].AnalystReview) -eq 'Yes') 'Unknown applicability remains visible for review'
    Check ((@($rows | Where-Object FindingId -eq 'V-001')[0].Score) -eq '95') 'V1 risk score is preserved for V-001'
    $bad = @(Import-Csv $inputPath)
    $bad[0].DaysOpen = '-2'
    $badPath = Join-Path $temp 'invalid.csv'
    $bad | Export-Csv $badPath -NoTypeInformation
    $rejected = $false
    try { & $scriptPath -InputPath $badPath -OutputPath (Join-Path $temp 'bad-output.csv') *>$null } catch { $rejected = $true }
    Check $rejected 'Invalid negative DaysOpen is rejected'
    Check ((@($rows | Where-Object {
        $_.FindingId -eq 'V-008' -and
        $_.Priority -eq 'P1' -and
        $_.AnalystReview -eq 'Yes'
    })).Count -eq 1) 'V-008 retains score-based P1 and requires analyst review'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "Tests passed: $passed; failed: $failed"
if ($failed -gt 0) { throw "$failed regression test(s) failed" }
