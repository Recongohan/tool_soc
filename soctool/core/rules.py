"""Catalogue of every detection rule and the MITRE ATT&CK techniques it maps to."""

from __future__ import annotations

from dataclasses import dataclass

from soctool.core.models import Finding, Severity

TECHNIQUES: dict[str, str] = {
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1078": "Valid Accounts",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1190": "Exploit Public-Facing Application",
    "T1204.002": "User Execution: Malicious File",
    "T1505.003": "Server Software Component: Web Shell",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1568.001": "Dynamic Resolution: Fast Flux DNS",
    "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    "T1572": "Protocol Tunneling",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, "")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    mitre: tuple[str, ...]
    description: str


_RULES = [
    # DNS
    Rule("DNS-001", "Possible DNS tunneling / exfiltration", ("T1071.004", "T1572", "T1048"),
         "Many long, high-entropy subdomains under one domain from one host: data is being encoded into DNS queries."),
    Rule("DNS-002", "High volume of TXT/NULL queries", ("T1071.004",),
         "TXT/NULL records carry arbitrary data and are a common DNS C2 channel."),
    Rule("DNS-003", "Possible DGA activity", ("T1568.002",),
         "Bursts of NXDOMAIN responses for random-looking domains: malware cycling through generated domains."),
    Rule("DNS-004", "DNS query to non-corporate resolver", ("T1071.004",),
         "A host bypassed the corporate resolver and talked to an external DNS server directly."),
    Rule("DNS-005", "Possible fast-flux domain", ("T1568.001",),
         "One domain resolving to many IPs spread across unrelated networks with short TTLs."),
    # Web
    Rule("WEB-001", "Directory / content brute forcing", ("T1595.003",),
         "Burst of 404 responses for many distinct paths from one client."),
    Rule("WEB-002", "Scanner or scripted user agent", ("T1595.002",),
         "Requests carry the user agent of a known attack tool or scripting library, not a browser."),
    Rule("WEB-003", "Possible web shell", ("T1505.003", "T1190"),
         "POST requests to a server-side script in a static/upload directory or with a known web shell name."),
    Rule("WEB-004", "Injection / exploit attempt", ("T1190",),
         "Request contains SQLi, XSS, path traversal, command injection or Log4Shell payloads."),
    Rule("WEB-005", "Login brute force against web app", ("T1110.001", "T1078"),
         "Many failed (401/403) requests to a login endpoint from one client, optionally followed by success."),
    Rule("WEB-006", "Sensitive file exposed", ("T1595.003", "T1552.001"),
         "A sensitive file (.env, .git, backups, phpinfo...) was served with HTTP 200."),
    # Auth
    Rule("AUTH-001", "Brute force against an account", ("T1110.001",),
         "Many failed logins for one account from one source in a short window."),
    Rule("AUTH-002", "Password spraying", ("T1110.003",),
         "One source failing logins across many different accounts in a short window."),
    Rule("AUTH-003", "Impossible travel", ("T1078",),
         "Successful logins for the same account from different countries closer in time than travel allows."),
    # Network
    Rule("NET-001", "Beaconing (C2 heartbeat)", ("T1071", "T1071.001"),
         "Connections from a host to one destination at highly regular intervals, typical of C2 implants."),
    # IOC
    Rule("IOC-001", "Suspicious domain", ("T1568.002", "T1583.001"),
         "Domain looks algorithmically generated, abuses a cheap TLD, uses punycode or imitates a brand."),
    Rule("IOC-002", "Reputation: flagged by threat intel", ("T1071",),
         "Indicator is reported malicious by an online threat-intelligence service."),
    Rule("DEC-001", "Encoded / obfuscated content", ("T1027", "T1059.001"),
         "Input contained encoded content (Base64 / PowerShell -EncodedCommand / URL / hex)."),
    # Phishing
    Rule("PHISH-001", "Email authentication failure", ("T1566",),
         "SPF, DKIM or DMARC did not pass: the sender may be spoofed."),
    Rule("PHISH-002", "Sender / reply-path mismatch", ("T1566", "T1036"),
         "From, Reply-To and Return-Path point at different domains: replies or bounces go elsewhere."),
    Rule("PHISH-003", "Brand impersonation / lookalike sender", ("T1036", "T1583.001"),
         "Display name or domain imitates a well-known brand that the sending domain does not belong to."),
    Rule("PHISH-004", "Suspicious link", ("T1566.002",),
         "Link text and target differ, link uses a raw IP, URL shortener, punycode, risky TLD or lookalike domain."),
    Rule("PHISH-005", "Dangerous attachment", ("T1566.001", "T1204.002"),
         "Executable, script, macro document, HTML or disk-image attachment, or a double extension."),
    Rule("PHISH-006", "Social-engineering language", ("T1566",),
         "Urgency / credential / payment pressure phrases in subject or body."),
]

RULES: dict[str, Rule] = {r.rule_id: r for r in _RULES}


def finding(rule_id: str, severity: Severity, entity: str, description: str,
            evidence: list[str] | None = None, first_seen: str | None = None,
            last_seen: str | None = None, title: str | None = None) -> Finding:
    """Build a Finding pre-filled with the rule's title and MITRE mapping."""
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=title or rule.title,
        severity=severity,
        entity=entity,
        description=description,
        mitre=list(rule.mitre),
        evidence=evidence or [],
        first_seen=first_seen,
        last_seen=last_seen,
    )
