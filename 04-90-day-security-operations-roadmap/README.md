# First 90 Days: Building a Measurable Security Operations Program

**Portfolio Project 04 | Security Operations Leadership + Hands-On Engineering**  
**Scenario:** Incoming Director of Enterprise Security at a healthcare technology organization  
**Status:** Proposed operating plan; not an assessment of any actual employer or organization

## Executive summary

My first 90 days would focus on understanding the business and its risks, validating the security controls already in place, improving a small number of high-value operational capabilities, and creating transparent reporting for leadership. The goal is not to arrive with a shopping list of tools. It is to learn what works, identify what does not, and deliver measurable improvements without disrupting the business.

**Operating principles**

1. **Patient and customer trust first.** Protect sensitive data and critical services while respecting availability and operational needs.
2. **People and ownership before tools.** Make sure alerts, incidents, vulnerabilities, and decisions have accountable owners.
3. **Risk over raw volume.** Prioritize exploitable vulnerabilities, important assets, and detections that address credible attack paths.
4. **Validate before claiming success.** Distinguish deployed controls, tested capabilities, and outcomes measured in production.
5. **Communicate in business terms.** Give executives an understandable view of exposure, decisions, trends, and remaining risk.

## Outcomes expected by day 90

- An agreed inventory of critical services, sensitive data flows, security owners, and major dependencies, with known gaps documented.
- A baseline assessment of security monitoring, incident response, identity, endpoint, cloud, and vulnerability management capabilities.
- A risk-ranked backlog with accountable owners, decision dates, and documented exceptions.
- Several **validated** detection or response improvements selected based on actual findings; exact number depends on environment and change capacity.
- At least one incident response tabletop or practical exercise, with lessons learned and follow-up owners.
- An executive-facing scorecard that reports metrics with clear definitions, data sources, and limitations.
- A proposed six-month improvement roadmap with staffing, tooling, process, and investment tradeoffs.

## Days 1–30 — Listen, map, and establish the baseline

### Executive and cross-functional work

- Meet the CISO/security sponsor, IT and engineering leaders, cloud/platform teams, privacy/compliance, legal, customer-facing teams, and incident stakeholders.
- Identify critical services, regulated/sensitive data, availability requirements, third-party dependencies, and business risk tolerances.
- Clarify incident escalation authority, after-hours coverage, decision ownership, and communication expectations.
- Review existing risk registers, audit findings, penetration test results, recent incidents, vendor assessments, and security commitments.
- Assess team responsibilities, skill coverage, operational bottlenecks, and on-call sustainability.

### Technical validation

- Map telemetry sources: identity provider, endpoints, cloud audit logs, applications, email, network, and relevant SaaS platforms.
- Check logging coverage, retention, ingestion health, alert routing, and whether investigators can obtain useful context.
- Walk through a recent alert from trigger to closure; note evidence gaps, handoffs, and unnecessary manual steps.
- Review vulnerability discovery scope, asset ownership, remediation workflows, and treatment of known-exploited findings.
- Assess EDR coverage, privileged access, MFA, cloud permissions, secrets handling, and incident response readiness.
- Select a small set of attack scenarios for safe validation, subject to approval and change controls.

### Deliverables and decision gate

**Deliverables:** Stakeholder map; critical-service and data-flow inventory (with confidence level); control and telemetry coverage matrix; incident response readiness assessment; baseline scorecard; top-risk register.

**Day-30 leadership discussion:** What are the most consequential gaps? Which can be fixed with process or configuration? What needs funding, staffing, or a risk acceptance decision?

## Days 31–60 — Fix important gaps and prove the changes work

### Executive and cross-functional work

- Agree on a short list of priority improvements with owners and realistic completion criteria.
- Establish a vulnerability remediation cadence with infrastructure, application, and cloud owners; prioritize exploitable critical findings, then other critical, high, and medium findings according to asset exposure and business context.
- Clarify incident severity definitions, escalation routes, evidence handling, and communication responsibilities.
- Identify repetitive SOC tasks suitable for automation, with human review where decisions could affect systems or users.

### Technical validation and delivery

- Tune high-value detections using documented test cases, representative benign activity, and regression checks.
- Improve investigation context: relevant identity, asset, process, and cloud activity available to analysts.
- Validate that tuning reduces known noise **without suppressing** nearby suspicious behaviors.
- Run a controlled incident scenario or tabletop and record gaps, decisions, and follow-up tasks.
- Prototype one low-risk automation (for example, evidence enrichment or case preparation) with logs, access controls, and rollback.
- Verify logging and alerting for priority cloud and identity attack paths; document untested assumptions.

### Deliverables and decision gate

**Deliverables:** Prioritized remediation backlog; detection test records; tuned detection change log; updated response playbooks; tabletop findings; automation pilot notes; refreshed scorecard.

**Day-60 leadership discussion:** Which changes have been validated? What operational friction remains? What risks require a business decision rather than another technical control?

## Days 61–90 — Operationalize, measure, and plan the next two quarters

### Executive and cross-functional work

- Review trends with business and technical owners, including overdue actions and unresolved high-impact risks.
- Define a sustainable operating cadence: daily triage, weekly operations review, monthly risk review, and quarterly executive reporting as appropriate.
- Confirm responsibilities, staffing coverage, skill development, and escalation paths.
- Present a six-month roadmap ranked by risk reduction, dependencies, effort, and cost.

### Technical validation and delivery

- Retest selected detections and response workflows after changes; preserve regression evidence.
- Review investigation quality and closure documentation for a sample of alerts.
- Verify the automation pilot's auditability, failure handling, and access restrictions before expansion.
- Conduct a follow-up exercise or targeted validation for the highest-priority unresolved scenario where feasible.
- Document known blind spots, control limitations, and accepted risks rather than reporting an unsupported coverage percentage.

### Deliverables and decision gate

**Deliverables:** Day-90 executive scorecard; evidence-backed improvement summary; detection/response runbooks; open-risk register; staffing and capability recommendations; six-month delivery roadmap.

**Day-90 leadership discussion:** What improved, what evidence supports that conclusion, what remains unaddressed, and what decisions are needed next?

## Executive security operations scorecard

The table below defines **proposed** metrics. There are intentionally no invented baselines or targets: those must be established after the environment is assessed.

| Dimension | Metric | Definition / calculation | Evidence source | Caveat |
|---|---|---|---|---|
| Visibility | Telemetry coverage of critical assets | Critical assets with required telemetry verified ÷ critical assets in agreed inventory | Asset inventory + log/EDR validation | Inventory completeness affects denominator |
| Detection | Validated priority detections | Count of approved detection scenarios with passing test evidence | Detection repository + test results | Not a percentage of all attacker techniques |
| Alert quality | Known benign alert volume | Alerts attributable to documented benign workflows during comparable periods | SIEM/case records | Compare like-for-like periods and event volume |
| Response | Time to triage | Time from alert creation to first documented analyst disposition | Case timestamps | Distinct from time to detect or contain |
| Response | Exercise follow-up closure | Completed exercise actions ÷ actions due by review date | Exercise tracker | Exercise results do not prove production performance |
| Vulnerabilities | Open exploitable critical findings | Count of open, validated exploitable critical findings in agreed scope | Scanner + exploit intelligence + exception register | Scanner coverage and duplicates must be checked |
| Vulnerabilities | Remediation within agreed SLA | Findings remediated on time ÷ findings due in period | Vulnerability workflow | Segment by severity and exposure |
| Operations | Evidence-backed automation savings | Observed time saved on measured workflow, net of review/rework | Pilot logs + sampled timings | Do not extrapolate from a small pilot |
| Governance | High-priority risks with owners | High-priority risks with assigned owner and next decision date ÷ all high-priority risks | Risk register | Ownership is not remediation |

### Example executive narrative (illustrative, not actual results)

> We established a baseline for critical telemetry and incident response, validated selected high-priority detections, and improved remediation ownership. The scorecard distinguishes confirmed improvements from work still in progress. The next decisions are where to invest in visibility, response capacity, and risk reduction.

## Sample technical workstream: Detection engineering

A practical improvement follows a repeatable cycle:

1. **Hypothesis:** Identify a suspicious behavior and the telemetry required to observe it.
2. **Build:** Implement the detection and document its assumptions.
3. **Test:** Run synthetic or otherwise approved scenarios; verify expected alerts.
4. **Tune:** Examine known benign activity and scope exceptions narrowly.
5. **Regression:** Confirm suspicious variants still alert after tuning.
6. **Operate:** Define owner, severity, response guidance, rollback, and review cadence.

This mirrors the [PowerShell detection engineering lab](../01-detection-engineering/) in this portfolio. That lab uses **synthetic data** and is evidence of engineering method, **not** proof of production detection coverage.

## Leadership experience informing this plan

In a previous healthcare security leadership role, I started by hiring two analysts, assessing capability gaps, and building a vulnerability management program. Working with IT partners, we introduced scanning, remediation coordination, and quarterly executive reporting. Over 12 months, we reduced **open critical-, high-, and medium-severity vulnerabilities by 82%**, prioritizing exploitable critical findings. The team eventually grew to 10 people.

Those experiences inform the emphasis here on people, operational ownership, risk prioritization, and transparent measurement. See the [security leadership case study](../03-security-leadership-case-study/).

## Risks and tradeoffs

- **Overpromising in 90 days:** Some improvements depend on vendor contracts, engineering capacity, and architecture changes. Use explicit decision gates rather than arbitrary completion promises.
- **Metrics without context:** A falling alert count can mean less noise—or a broken data pipeline. Pair volume metrics with telemetry health and regression evidence.
- **Operational disruption:** Coordinate scanning, remediation, and response testing with service owners and change controls.
- **Privacy and sensitive data:** Apply least privilege, appropriate retention, and controlled access to investigation artifacts.
- **Automation risk:** Keep humans accountable for consequential actions; test failure paths and log decisions.
- **Tool-first thinking:** Prefer understanding current investments and processes before adding platforms.
