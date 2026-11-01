# 4. Decoys: detections that almost never lie

> Part of the series *How I built the detections*. Drafted with an AI assistant from this repository's commit history; every number is copied from a generated report linked in the post. All data is synthetic.

Most rules trade sensitivity for noise. Decoys do not have that problem: nobody has a legitimate
reason to sign in as a honey account, open a file called `vpn_credentials.txt` that no process
needs, or use an access key that was planted in an old backup.

**The rules.** SOC-RULE-046 alerts on any logon, ticket request or failed logon for a decoy
account. SOC-RULE-047 alerts on object access (Event 4663) to canary files. SOC-RULE-048 alerts on
any CloudTrail call made by the IAM user that owns a planted, permissionless access key.

**The catch.** The decoy names in a public repository are known to anyone who reads it, so the
rules ship with placeholders and [CANARIES.md](../CANARIES.md) explains how to deploy your own:
an account with no rights and logon hours set to never, a SACL on each canary file, and an IAM
user with no policies, because a decoy must never be a working credential.

**Lesson.** The cheapest high-fidelity detection is often a lie you tell the attacker.
