# Post-Incident Review: <incident name>

> Blameless review. We look for what in the system made the outcome likely, not for whom to
> blame. For CyberPulse cases, `GET /api/cases/<case_id>/review` pre-fills the factual sections.

| | |
| :--- | :--- |
| Case / incident ids | |
| Severity | |
| Date of review | |
| Facilitator | |
| Participants | |
| Real or exercise | |

## 1. Summary
Two or three sentences in plain language: what happened, who or what was affected, how it ended.

## 2. Impact
People, systems and data affected; duration; any harm caused by our own response (outage,
lockout, quarantined mail).

## 3. Timeline (event time, UTC)
| When | What happened | Source (log, alert, person) |
| :--- | :--- | :--- |

## 4. Detection
- How was it first noticed (rule, hunt, user report, third party)?
- Detection delay per step; which steps were not detected at all?

## 5. Response
- Each containment decision: who, what, why, how long it took to approve, outcome.
- Was any automated action wrong, late or unnecessary? Link the appeal.

## 6. What went well

## 7. What was hard

## 8. Where we were lucky

## 9. Contributing factors
Missing telemetry, noisy rules, unclear runbooks, slow approvals, access problems...

## 10. Actions
| Action | Owner | Due | Ticket / PR |
| :--- | :--- | :--- | :--- |

Close the loop: link new rules, exceptions or playbook changes, and update
`docs/RISK_REGISTER.md` if a risk was re-rated.
