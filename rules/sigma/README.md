# Sigma Rules: Provenance & Credit

Every rule in this folder was written for the CyberPulse lab and has only been
tested against the lab's synthetic events (`status: experimental`). No rule
records an upstream source, and none was knowingly copied from another
repository.

## Credit where the ideas come from

The detection logic follows patterns that are widely published by the
detection-engineering community. Credit for those public patterns goes in
particular to:

* **SigmaHQ** (<https://github.com/SigmaHQ/sigma>): the Sigma format and the
  community rule set, whose rules for LSASS access, Kerberoasting (RC4 TGS
  requests), DCSync (replication extended rights), Defender tampering and
  vulnerable driver loads cover the same techniques.
* **MITRE ATT&CK** (<https://attack.mitre.org>): technique descriptions linked
  from each rule's `references`.
* Microsoft documentation for the Windows Security and Sysmon event IDs used.

If you recognise a rule here as substantially derived from a specific
published rule, please open an issue so its original author can be credited.

## Rules for adapting upstream rules

SigmaHQ rules are licensed under the **Detection Rule License (DRL) 1.1**.
When a rule is adapted from one in future, it must:

1. keep the original `author` and add ours (e.g. `author: Original Author, lumidren`),
2. list the original rule's URL first under `references`,
3. note what was changed in the description or a comment.

`tests/test_sigma_metadata.py` checks that every rule has an `author` and at
least one `references` URL.

## Correlation rules

Multi-event rules (brute force on raw 4625s, password spraying, mass file writes) live in
[`correlations/`](correlations/README.md) and are evaluated by `soar/sigma_correlation.py`.
