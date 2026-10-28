# Project 02 — Risk-Based Vulnerability Prioritization (PowerShell V2)

A **synthetic, read-only security operations lab** that turns vulnerability findings into an explainable, risk-ranked remediation queue. It demonstrates how an analyst can combine severity, exploitation context, asset importance, exposure, and age to support remediation triage. **No real assets are scanned, changed, or remediated.**

## What it does

- Reads a CSV of synthetic vulnerability findings and validates required fields, supported values, unique finding IDs, and nonnegative days open.
- Calculates an additive risk score and assigns P1/P2/P3 priorities.
- Elevates confirmed applicable, actively exploited findings to P1 when the asset is internet-facing **or** high criticality.
- Retains uncertain or reportedly non-applicable findings in the queue and flags them for analyst review rather than suppressing them.
- Exports an ordered CSV with score, priority, analyst-review flag, and decision reason.
- Includes **nine regression assertions** covering sample findings, prioritization, analyst review, score preservation, and invalid input rejection.

## Files

| File | Purpose |
| --- | --- |
| `Prioritize-Vulnerabilities-V2.ps1` | Main scoring and queue-generation script |
| `sample-vulnerabilities-v2.csv` | Eight synthetic input findings |
| `remediation-queue-v2.csv` | Example generated output from the synthetic input |
| `Test-Prioritization-V2.ps1` | Nine regression assertions |

## Run locally

From PowerShell in this folder:

```powershell
.\Prioritize-Vulnerabilities-V2.ps1
Import-Csv .\remediation-queue-v2.csv | Format-Table FindingId,Asset,Score,Priority,AnalystReview -AutoSize
.\Test-Prioritization-V2.ps1
```

If Windows blocks downloaded scripts, inspect the files first and then use `Unblock-File` on the specific `.ps1` files. The scripts also accept custom paths:

```powershell
.\Prioritize-Vulnerabilities-V2.ps1 -InputPath .\sample-vulnerabilities-v2.csv -OutputPath .\my-queue.csv
```

## Illustrative scoring policy

| Factor | Points |
| --- | --- |
| Severity: Critical / High / Medium / Low | 40 / 25 / 10 / 2 |
| Asset criticality: High / Medium / Low | 20 / 10 / 0 |
| Known exploited in the wild | +35 |
| Days open: 60+ / 30–59 / under 30 | +10 / +5 / 0 |

**Base priority:** P1 if score is 65 or greater **or** severity is Critical and `KnownExploited=True`; P2 if score is 35–64; otherwise P3. A conditional **P1 override** applies when `ActiveExploitation=True`, `Applicability=Confirmed`, and either `Exposure=Internet` or `AssetCriticality=High`.

`KnownExploited` and `ActiveExploitation` are different inputs. The latter is **synthetic, analyst-provided context**; the script does not independently confirm exploitation through telemetry. Active exploitation without confirmed applicability triggers analyst review instead of the conditional override. **Score-based P1 can still apply independently**: V-008 is P1 based on its score of 70 and is also flagged for analyst review because applicability is unknown. An `Applicability=NotApplicable` finding is retained for evidence validation, not automatically closed or removed.

These priorities are educational examples, not universal remediation deadlines or incident classifications.

## Expected synthetic results

| Measure | Result |
| --- | ---: |
| Findings analyzed | 8 |
| P1 / P2 / P3 | 3 / 3 / 2 |
| Analyst review flagged | 2 |
| Regression assertions | 9 |

- **V-001:** P1, score 95, preserving the original additive scoring logic.
- **V-007:** P1 via the conditional active-exploitation override despite a base score of 55.
- **V-008:** P1 via score 70; separately flagged for analyst review because applicability is unknown.
- **V-005:** P2; known exploitation in the wild alone does not activate the conditional P1 override.
- **V-003:** P3, flagged for analyst review because applicability is unknown.

## Operational value

A repeatable, explainable remediation queue helps security and infrastructure teams discuss *why* a finding is prioritized, identify uncertain data needing analyst attention, and route work to the listed owner. The lab separates deterministic scoring from decisions that require human validation.

## Scope and limitations

This is a portfolio demonstration using fictional `LAB-` assets and synthetic findings. It does **not** integrate with vulnerability scanners, asset inventories, KEV/EPSS/CVSS feeds, SIEM/EDR, ticketing, authentication, risk acceptance, or remediation systems. A production implementation would need trusted input provenance, policy review, exception expiration, accountable owners, audit trails, and tests for additional edge cases. Sample outputs are illustrative and must not be interpreted as results from a live environment.
