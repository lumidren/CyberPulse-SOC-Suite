# Legal Notices

## MITRE ATT&CK®

This project references MITRE ATT&CK® technique and tactic identifiers, names
and short descriptions (for example in `rules/`, `simulator/`, the coverage
documents and the triage-summary knowledge base in `soar/ai_copilot.py`).

© The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation. ATT&CK® and MITRE ATT&CK® are registered
trademarks of The MITRE Corporation. Use of ATT&CK is subject to the ATT&CK
Terms of Use (<https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>).
Technique descriptions in this repository are short summaries; the
authoritative text is at <https://attack.mitre.org>.

## Trademarks

Microsoft, Windows, Active Directory, Microsoft Entra ID, Microsoft Defender,
Sysmon and Sysinternals are trademarks of the Microsoft group of companies.
Fortinet and FortiGate are trademarks of Fortinet, Inc. pfSense is a
trademark of Electric Sheep Fencing LLC / Netgate. VirusTotal is a trademark
of Chronicle LLC / Google. AbuseIPDB is a trademark of its owner. Amazon Web
Services and AWS are trademarks of Amazon.com, Inc. or its affiliates. Wazuh,
Splunk, TheHive, MISP, OpenSearch, Velociraptor, osquery, BloodHound, Shuffle,
Discord and Slack are trademarks of their respective owners. MITRE ATT&CK® is a
registered trademark of The MITRE Corporation.

These names are used only to identify the products this lab is configured to
work with (nominative use). No endorsement is implied.

## No warranty; no liability for automated actions

This software is provided "AS IS", without warranty of any kind, as stated in
the MIT [LICENSE](../LICENSE). In particular, and in plain words:

* The detection rules, risk scores and containment playbooks are lab material.
  They may miss real attacks and may flag legitimate activity.
* Automated or approved containment (host isolation, firewall blocks, account
  lockout, token revocation, process termination) **can disrupt business
  operations, lock people out and destroy data or evidence** if misconfigured
  or wrong. The safety controls (approval by default, kill switch, rate
  limits, protected assets, TTLs, rollback) reduce that risk; they do not
  remove it.
* The author and contributors accept **no liability** for any outage, data
  loss, wrongful lockout, missed detection, or other damage arising from use
  of this software. If you wire the responders to real systems, you do so at
  your own risk and are responsible for testing, change control and approval.

## Authorisation required before deployment

Do **not** deploy any part of CyberPulse (simulator, agents, Sysmon/Wazuh
configurations, playbooks, responders or ingestion) on a network, host,
cloud account or tenant unless you **own it or have explicit written
authorisation** from its owner to do so. Unauthorised monitoring, simulated
attacks or containment actions can be illegal (for example under computer
misuse, wiretapping or data-protection laws) and can breach employment or
service agreements, even when no harm is intended.

If you are unsure whether you are authorised, you are not. Use the bundled
synthetic lab, or an isolated environment you control.

