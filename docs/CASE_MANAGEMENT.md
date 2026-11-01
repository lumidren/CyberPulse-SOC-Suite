# Case Management

Roadmap F35. Every incident is filed into a case automatically
(`soar/case_manager.py`). Incidents for the same host (or, without a host, the
same source IP) within two hours of the case's last activity join that case, so
one intrusion is one ticket rather than one ticket per alert.

A case holds: its incidents, rules, ATT&CK techniques, hosts and source IPs; the
highest severity and risk score; every proposed or executed response with its
status; the merged playbook task list (`playbooks/*.yml`); and a timeline of
everything that happened to it and who did it.

| Endpoint | What it does |
| :--- | :--- |
| `GET /api/cases[?status=New]` | List cases, most recently updated first |
| `GET /api/cases/<id>` | One case |
| `POST /api/cases/<id>` | `{"analyst", "status", "assignee", "note", "task", "task_status"}`: change status (New, Investigating, Resolved, Closed; Closed is final), assign, add a note, mark a task Done |

Every change is written to the case timeline with the actor and to the audit
log. Account names are masked in API responses like incident data. Cases are in
memory and are purged when retention removes all of their incidents; export
them (or use TheHive, F36) if you need them to outlive the process.
