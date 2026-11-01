"""
Phishing triage (roadmap F46): header and URL analysis for a reported or detected email.

Runs offline on the message metadata the pipeline already has (no message body, no
network calls) and returns findings an analyst can check in seconds:

  * authentication: SPF, DKIM and DMARC results parsed from ``AuthenticationResults``;
  * sender: Reply-To on a different domain, a display name that embeds another address
    or names a watched person, and look-alike domains of your own (edit distance and
    common character swaps such as rn->m, 0->o, 1->l, plus punycode);
  * URLs: raw IP hosts, punycode, ``@`` tricks, known shorteners, and links to a domain
    other than the sender's. URLs are shown defanged (``hxxps://evil[.]example``).

URL detonation is a separate, opt-in step through the lab sandbox (soar/sandbox.py, F47);
``triage`` only records whether one was requested. The verdict is a 0-100 score with the
reason for every point, never an automatic action.

Configuration: ``PHISHING_ORG_DOMAINS`` (your mail domains, comma separated) and
``PHISHING_WATCHED_NAMES`` (executives / finance names often impersonated).
"""

import os
import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)
ADDRESS_RE = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.I)


def _env_list(name, default=""):
    return [x.strip().lower() for x in os.environ.get(name, default).split(",") if x.strip()]


def domain_of(address):
    return str(address or "").rsplit("@", 1)[-1].strip().lower().rstrip(">")


def defang(url):
    return str(url).replace("http", "hxxp", 1).replace(".", "[.]")


def _levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalise(domain):
    out = domain.lower()
    for fake, real in HOMOGLYPHS:
        out = out.replace(fake, real)
    return out


def lookalike_of(domain, org_domains):
    """The org domain this one imitates, or None (exact matches are not look-alikes)."""
    domain = domain.lower()
    if not domain or domain in org_domains:
        return None
    for org in org_domains:
        base, org_base = domain.split(".")[0], org.split(".")[0]
        if domain.startswith("xn--") or _normalise(domain) == org or _normalise(base) == org_base:
            return org
        if len(org_base) >= 4 and _levenshtein(base, org_base) <= 2:
            return org
        if org_base in base and base != org_base:  # corp-example-billing.net
            return org
    return None


def triage(details, org_domains=None, watched_names=None):
    org_domains = [d.lower() for d in (org_domains if org_domains is not None else _env_list("PHISHING_ORG_DOMAINS", "corp.example"))]
    watched = [n.lower() for n in (watched_names if watched_names is not None else _env_list("PHISHING_WATCHED_NAMES"))]
    findings = []

    def find(points, reason):
        findings.append({"points": points, "reason": reason})

    auth = {k.lower(): v.lower() for k, v in AUTH_RE.findall(str(details.get("AuthenticationResults", "")))}
    for check in ("spf", "dkim", "dmarc"):
        if auth.get(check) in ("fail", "softfail", "none", "permerror"):
            find(20 if check == "dmarc" else 10, f"{check.upper()} {auth[check]}")

    sender = str(details.get("SenderFromAddress", ""))
    sender_domain = domain_of(sender)
    reply_domain = domain_of(details.get("ReplyToAddress")) if details.get("ReplyToAddress") else None
    if reply_domain and reply_domain != sender_domain:
        find(15, f"Reply-To goes to a different domain ({reply_domain})")
    display = str(details.get("SenderDisplayName", ""))
    embedded = ADDRESS_RE.search(display)
    if embedded and domain_of(embedded.group(0)) != sender_domain:
        find(20, f"display name shows another address ({embedded.group(0)})")
    if any(name and name in display.lower() for name in watched) and sender_domain not in org_domains:
        find(25, "display name matches a watched person but the mail is external")
    imitated = lookalike_of(sender_domain, org_domains)
    if imitated:
        find(30, f"sender domain {sender_domain} imitates {imitated}")

    urls = []
    for url in details.get("Urls") or []:
        parsed = urlparse(str(url))
        host = (parsed.hostname or "").lower()
        flags = []
        if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host or "x"):
            flags.append("raw IP host")
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("punycode host")
        if "@" in parsed.netloc:
            flags.append("'@' in the address hides the real host")
        if host in SHORTENERS:
            flags.append("URL shortener")
        if host and sender_domain and not host.endswith(sender_domain):
            flags.append("links to a domain other than the sender's")
        if lookalike_of(host, org_domains):
            flags.append(f"host imitates {lookalike_of(host, org_domains)}")
        urls.append({"url": defang(url), "host": host.replace(".", "[.]"), "flags": flags})
        for flag in flags:
            if flag != "links to a domain other than the sender's":
                find(10, f"URL {defang(url)}: {flag}")
    if details.get("AttachmentSha256"):
        find(5, "has an attachment (hash available for lookup)")

    score = min(100, sum(f["points"] for f in findings))
    return {
        "score": score,
        "verdict": "likely phishing" if score >= 50 else ("suspicious" if score >= 25 else "no strong indicators"),
        "authentication": auth,
        "findings": findings,
        "urls": urls,
        "detonation": "not requested (see soar/sandbox.py)",
        "note": "Heuristics on metadata only; a low score does not make a message safe.",
    }
