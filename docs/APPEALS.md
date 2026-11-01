# Appeals: When Automation Got It Wrong

Roadmap E98. Analysts can say an automated decision was wrong, and the loop only closes
when the rule, exception or playbook is fixed (`soar/appeals.py`).

| Step | Who | API |
| :--- | :--- | :--- |
| 1. Open an appeal on an incident: `false_positive`, `wrong_action`, `wrong_target` or `too_late`, with a reason | any analyst | `POST /api/incidents/<id>/appeal` `{"analyst", "kind", "reason"}` |
| 2. Accept or reject it, with a reason | a **lead** | `POST /api/appeals/<id>/decide` `{"analyst", "accept", "reason"}` |
| 3. Fix it: commit the exception, rule or playbook change | whoever tunes | normal review ([TUNING.md](TUNING.md)) |
| 4. Mark it tuned with a reference (commit, exception id, PR) | anyone | `POST /api/appeals/<id>/tuned` `{"analyst", "reference"}` |

- Opening an appeal does **not** undo anything; rolling back containment is a separate,
  deliberate step, so one complaint cannot quietly reverse a correct isolation.
- An accepted false-positive appeal includes a **draft** exception built from the
  incident's stable fields (parent image, task name, sender...). It is a suggestion: narrow
  it to fields an attacker cannot easily copy, then commit it. Nothing is applied
  automatically, and the test suite rejects any exception that would hide the rule's own
  attack samples.
- Every step is written to the tamper-evident action ledger (`GET /api/audit/actions`).
- `GET /api/appeals` lists appeals and counts per rule (open, accepted, rejected, tuned):
  the rules analysts distrust most, and whether their complaints get fixed.
