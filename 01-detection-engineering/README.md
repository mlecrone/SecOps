# PowerShell detection engineering — synthetic lab

## Objective
Demonstrate detection development, controlled tuning, regression testing, and executive communication using **fictional endpoint events only**. This is a learning exercise, not a production-ready security control.

## Development progression
1. **Baseline:** Seven synthetic events produced four alerts for encoded PowerShell.
2. **False-positive exercise:** An eighth, deliberately benign encoded maintenance event produced a fifth alert.
3. **Narrow tuning:** The approved maintenance event is retained in an audit CSV rather than the analyst alert queue. On the same eight-event dataset, the alert queue changes from five to four (a **20% reduction in this tiny synthetic example**).
4. **Regression test:** A ninth event from the *same administrator* with a different encoded command still triggers an alert. The five test assertions passed in the author's Windows lab.

## Reproduce the lab
In PowerShell, from this folder:

```powershell
.\Detect-SuspiciousPowerShell-V3.ps1
.\Test-Detection-V3.ps1
```

The first command should report **8 events, 4 alerts, 1 approved activity record**. The regression test creates a ninth event and checks **5 alerts, 1 approved activity record, and 5 passing assertions**. Generated CSV reports are not required to be checked into the repository.

If Windows blocks downloaded scripts, inspect the source before running. On a personally managed machine where permitted, `Unblock-File` may be used for each reviewed script. Do not weaken centrally managed execution policies.

## Security decisions and limitations
- Encoded PowerShell alone is not proof of compromise. Severity is a heuristic for analyst prioritization.
- Decoded Base64 is **never executed**.
- The lab exception uses an exact host, username, process name, decoded command, and absence of bypass. These attributes are spoofable and **do not prove authorization**. Production tuning requires trusted provenance, change approvals, and ongoing validation.
- The simple regex is not a complete PowerShell parser. These tests do not establish production precision, recall, false-positive rate, or incident response performance.
- The accompanying workbook is a **synthetic executive scorecard**, not employer or patient data.

## Files
- `Detect-SuspiciousPowerShell-V3.ps1` — tuned detector
- `Test-Detection-V3.ps1` — regression test
- `sample-events-v3.csv` — eight fictional events
- `PowerShell_SOC_Executive_Scorecard.xlsx` — illustrative leadership scorecard

## Next improvements
Add labeled benign and malicious test cases, parser edge-case tests, and trusted execution context before proposing real-world use.
