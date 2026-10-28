# Portfolio lab: synthetic findings only. Generates reports; never remediates assets.
[CmdletBinding()]
param([string]$InputPath, [string]$OutputPath)
if ([string]::IsNullOrWhiteSpace($InputPath)) { $InputPath = Join-Path $PSScriptRoot 'sample-vulnerabilities-v2.csv' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $PSScriptRoot 'remediation-queue-v2.csv' }
if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw "Input not found: $InputPath" }
$items = @(Import-Csv -LiteralPath $InputPath)
$required = @('FindingId','Asset','Severity','KnownExploited','AssetCriticality','DaysOpen','Owner','Applicability','Exposure','ActiveExploitation')
if ($items.Count -eq 0) { throw 'Input CSV contains no findings' }
foreach ($field in $required) { if (-not $items[0].PSObject.Properties[$field]) { throw "Missing CSV column: $field" } }
$ids = @{}
$queue = @(
    foreach ($item in $items) {
        foreach ($field in $required) { if ([string]::IsNullOrWhiteSpace([string]$item.$field)) { throw "Blank $field for finding $($item.FindingId)" } }
        if ($ids.ContainsKey($item.FindingId)) { throw "Duplicate FindingId: $($item.FindingId)" }
        $ids[$item.FindingId] = $true
        $severity = $item.Severity.Trim().ToLowerInvariant()
        $criticality = $item.AssetCriticality.Trim().ToLowerInvariant()
        $applicability = $item.Applicability.Trim().ToLowerInvariant()
        $exposure = $item.Exposure.Trim().ToLowerInvariant()
        $severityPoints = switch ($severity) { 'critical' {40} 'high' {25} 'medium' {10} 'low' {2} default {throw "Invalid Severity for $($item.FindingId)"} }
        $assetPoints = switch ($criticality) { 'high' {20} 'medium' {10} 'low' {0} default {throw "Invalid AssetCriticality for $($item.FindingId)"} }
        if ($applicability -notin @('confirmed','unknown','notapplicable')) { throw "Invalid Applicability for $($item.FindingId)" }
        if ($exposure -notin @('internet','internal','isolated')) { throw "Invalid Exposure for $($item.FindingId)" }
        $known = $false; $active = $false
        if (-not [bool]::TryParse($item.KnownExploited.Trim(), [ref]$known)) { throw "Invalid KnownExploited for $($item.FindingId)" }
        if (-not [bool]::TryParse($item.ActiveExploitation.Trim(), [ref]$active)) { throw "Invalid ActiveExploitation for $($item.FindingId)" }
        $days = 0
        if (-not [int]::TryParse($item.DaysOpen.Trim(), [ref]$days) -or $days -lt 0) { throw "Invalid DaysOpen for $($item.FindingId)" }
        $score = $severityPoints + $assetPoints + $(if ($known) {35} else {0}) + $(if ($days -ge 60) {10} elseif ($days -ge 30) {5} else {0})
        $tier = if ($known -and $severity -eq 'critical') {'P1'} elseif ($score -ge 65) {'P1'} elseif ($score -ge 35) {'P2'} else {'P3'}
        $reason = 'Score-based priority'
        $review = 'No'
        if ($applicability -eq 'notapplicable') {
            # Never silently suppress a finding; keep it in the report for validation.
            $review = 'Yes'; $reason = 'Reported not applicable; validate evidence before closure'
        } elseif ($active -and $applicability -eq 'confirmed' -and ($exposure -eq 'internet' -or $criticality -eq 'high')) {
            $tier = 'P1'; $reason = 'P1 override: active exploitation, confirmed applicability, and exposure or high asset criticality'
        } elseif ($active) {
            $review = 'Yes'; $reason = 'Active exploitation reported; investigate applicability and asset context immediately'
        } elseif ($applicability -eq 'unknown') {
            $review = 'Yes'; $reason = 'Applicability unknown; validate before remediation decision'
        }
        [pscustomobject]@{
            FindingId=$item.FindingId; Asset=$item.Asset; Owner=$item.Owner; Severity=$item.Severity
            KnownExploited=$known; ActiveExploitation=$active; Applicability=$item.Applicability
            Exposure=$item.Exposure; AssetCriticality=$item.AssetCriticality; DaysOpen=$days
            Score=$score; Priority=$tier; AnalystReview=$review; DecisionReason=$reason
        }
    }
)
$ordered = @($queue | Sort-Object @{Expression={switch ($_.Priority) {'P1' {1} 'P2' {2} default {3}}}}, @{Expression='Score';Descending=$true}, FindingId)
$ordered | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Findings analyzed: $($items.Count)"
Write-Host "P1: $(@($ordered | Where-Object Priority -eq 'P1').Count); P2: $(@($ordered | Where-Object Priority -eq 'P2').Count); P3: $(@($ordered | Where-Object Priority -eq 'P3').Count)"
Write-Host "Analyst review flagged: $(@($ordered | Where-Object AnalystReview -eq 'Yes').Count)"
Write-Host "Report: $OutputPath"
