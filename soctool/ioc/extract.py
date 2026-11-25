"""Extract, refang and defang indicators of compromise from free text."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_REFANG = [
    (re.compile(r"h(xx|\*\*|XX)p(s?)", re.I), r"http\2"),
    (re.compile(r"f(xx|XX)p", re.I), "ftp"),
    (re.compile(r"\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}|\s\[dot\]\s", re.I), "."),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[(@|at)\]|\((@|at)\)", re.I), "@"),
]

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
IPV6 = re.compile(r"(?<![:\w])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![:\w])", re.I)
URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\[)(]+", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})\b", re.I)
MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# "TLDs" that are almost always file extensions in incident text.
_FILE_EXT = {
    "exe", "dll", "sys", "txt", "log", "php", "html", "htm", "js", "json", "xml", "csv", "png", "jpg",
    "jpeg", "gif", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "py", "ps1",
    "bat", "cmd", "vbs", "ini", "cfg", "tmp", "dat", "bin", "lnk", "hta", "eml", "msg", "jar", "rar",
    "gz", "tar", "7z", "iso", "img", "msi", "aspx", "asp", "jsp", "sh", "md", "yml", "yaml", "conf",
    "local", "internal", "lan", "corp", "invalid", "localhost",
}


@dataclass
class IOCSet:
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    def items(self):
        return [(k, v) for k, v in self.__dict__.items()]

    def total(self) -> int:
        return sum(len(v) for v in self.__dict__.values())


def refang(text: str) -> str:
    for rx, repl in _REFANG:
        text = rx.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste into tickets/chat (no auto-linking)."""
    m = re.match(r"^(?P<scheme>[a-z]+)://(?P<host>[^/?#]+)(?P<rest>.*)$", value, re.I)
    if m:
        scheme = m.group("scheme").lower().replace("http", "hxxp").replace("ftp", "fxp")
        return f"{scheme}[://]{m.group('host').replace('.', '[.]')}{m.group('rest')}"
    return value.replace("@", "[@]").replace(".", "[.]")


def _dedupe(values) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        seen.setdefault(v, None)
    return list(seen)


def extract(text: str, include_private: bool = False) -> IOCSet:
    text = refang(text)
    out = IOCSet()
    out.urls = _dedupe(u.rstrip(".,;:!?'\")]") for u in URL.findall(text))
    out.emails = _dedupe(e.lower() for e in EMAIL.findall(text))

    ips = []
    for ip in IPV4.findall(text):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if include_private or addr.is_global:
            ips.append(ip)
    out.ipv4 = _dedupe(ips)
    v6 = []
    for cand in IPV6.findall(text):
        try:
            addr = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if include_private or addr.is_global:
            v6.append(str(addr))
    out.ipv6 = _dedupe(v6)

    out.sha256 = _dedupe(h.lower() for h in SHA256.findall(text))
    out.sha1 = _dedupe(h.lower() for h in SHA1.findall(text))
    out.md5 = _dedupe(h.lower() for h in MD5.findall(text))
    out.cves = _dedupe(c.upper() for c in CVE.findall(text))

    email_domains = {e.split("@", 1)[1] for e in out.emails}
    domains = []
    for m in DOMAIN.finditer(text):
        raw = m.group(0)
        # CamelCase labels are code (Net.WebClient, System.IO.File), not hostnames.
        if any(re.search(r"[a-z][A-Z]", label) for label in raw.split(".")):
            continue
        d = raw.lower().rstrip(".")
        if d.rsplit(".", 1)[-1] in _FILE_EXT or IPV4.fullmatch(d):
            continue
        domains.append(d)
    # Keep domains that also appear in emails/URLs - analysts usually block both.
    out.domains = _dedupe(domains + sorted(email_domains))
    return out


def classify(value: str) -> str:
    """Best-effort type of a single indicator: ip, domain, url, email, md5, sha1, sha256, cve, unknown."""
    v = refang(value.strip())
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if URL.fullmatch(v):
        return "url"
    if EMAIL.fullmatch(v):
        return "email"
    if SHA256.fullmatch(v):
        return "sha256"
    if SHA1.fullmatch(v):
        return "sha1"
    if MD5.fullmatch(v):
        return "md5"
    if CVE.fullmatch(v):
        return "cve"
    if DOMAIN.fullmatch(v):
        return "domain"
    return "unknown"
