"""Phishing triage for .eml files: headers, authentication, links, attachments, language."""

from __future__ import annotations

import email
import hashlib
import ipaddress
import re
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.core.textutil import (BRANDS, SUSPICIOUS_TLDS, base_domain, brand_lookalike, is_ip, tld)
from soctool.ioc.extract import URL, defang

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly",
              "buff.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de"}
FREE_HOSTING = {"000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
                "netlify.app", "vercel.app", "pages.dev", "workers.dev", "glitch.me", "github.io",
                "sharepoint.com", "blogspot.com", "ngrok.io", "ngrok-free.app", "ipfs.io", "r2.dev",
                "duckdns.org", "herokuapp.com", "azurewebsites.net", "trycloudflare.com"}

EXEC_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
            "ps1", "msi", "lnk", "dll", "cpl", "jar", "reg", "sct", "chm", "appx", "msix"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb", "xll"}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "gz", "cab", "ace", "tar"}
HTML_EXT = {"html", "htm", "shtml", "svg", "xhtml", "mht"}

URGENCY = [
    "urgent", "immediately", "action required", "verify your account", "verify your identity",
    "confirm your identity", "account suspended", "account will be suspended", "unusual activity",
    "unusual sign-in", "password expires", "password expired", "reset your password", "within 24 hours",
    "within 48 hours", "final notice", "click here", "update your payment", "payment failed",
    "invoice attached", "wire transfer", "gift card", "your mailbox is full", "security alert",
    "locked", "unauthorized", "pending payment", "shared a document", "voicemail",
]

WEIGHTS = {Severity.CRITICAL: 40, Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 5, Severity.INFO: 0}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href = a["href"].strip()
            self._text = []
        elif tag == "form":
            self.forms.append(a.get("action") or "")

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def _domain_of(addr: str) -> str:
    addr = addr.strip().strip("<>")
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    results: dict[str, str] = {}
    headers = (msg.get_all("Authentication-Results") or []) + (msg.get_all("ARC-Authentication-Results") or [])
    for header in headers:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", str(header), re.I)
            if m and mech not in results:
                results[mech] = m.group(1).lower()
    if "spf" not in results:
        rspf = msg.get("Received-SPF")
        if rspf:
            results["spf"] = str(rspf).split()[0].lower()
    return results


def _received_hops(msg: EmailMessage) -> list[dict[str, str]]:
    hops = []
    for header in reversed(msg.get_all("Received") or []):  # oldest first
        text = " ".join(str(header).split())
        frm = re.search(r"from\s+(\S+)", text, re.I)
        by = re.search(r"\bby\s+(\S+)", text, re.I)
        ips = re.findall(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?", text)
        hops.append({"from": frm.group(1) if frm else "?", "by": by.group(1) if by else "?",
                     "ip": next((ip for ip in ips if _is_public(ip)), ips[0] if ips else "")})
    return hops


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _bodies(msg: EmailMessage) -> tuple[str, str, list[dict]]:
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "name": filename or "(unnamed)",
                "type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),  # noqa: S324 - IOC, not security
            })
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/html":
            html_parts.append(str(content))
        elif ctype.startswith("text/"):
            text_parts.append(str(content))
    return "\n".join(text_parts), "\n".join(html_parts), attachments


def _url_reasons(url: str, from_base: str) -> list[tuple[Severity, str]]:
    reasons: list[tuple[Severity, str]] = []
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return reasons
    base = base_domain(host)
    if "@" in parts.netloc:
        reasons.append((Severity.HIGH, "userinfo '@' trick hides the real host"))
    if is_ip(host):
        reasons.append((Severity.HIGH, "raw IP address as host"))
    else:
        look = brand_lookalike(host)
        if look:
            reasons.append((Severity.HIGH, look[1]))
        if "xn--" in host:
            reasons.append((Severity.HIGH, "punycode (IDN homograph) domain"))
        if base in SHORTENERS:
            reasons.append((Severity.MEDIUM, "URL shortener hides destination"))
        if base in FREE_HOSTING:
            reasons.append((Severity.MEDIUM, f"free hosting / file share ({base})"))
        if tld(host) in SUSPICIOUS_TLDS:
            reasons.append((Severity.MEDIUM, f"high-abuse TLD .{tld(host)}"))
    if parts.scheme == "http" and re.search(r"login|signin|verify|account|password|secure|update", url, re.I):
        reasons.append((Severity.MEDIUM, "credential-themed path over plain HTTP"))
    if re.search(r"\.(exe|scr|js|vbs|hta|iso|img|zip|rar|msi|lnk)(\?|$)", parts.path, re.I):
        reasons.append((Severity.HIGH, "link downloads an executable / archive"))
    return reasons


def analyze(path: str) -> Report:
    with open(path, "rb") as fh:
        msg: EmailMessage = email.message_from_binary_file(fh, policy=policy.default)  # type: ignore[assignment]

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain_of(from_addr)
    from_base = base_domain(from_dom) if from_dom else ""
    reply_to = [a for _, a in getaddresses([str(h) for h in (msg.get_all("Reply-To") or [])])]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    subject = str(msg.get("Subject", ""))
    auth = _auth_results(msg)
    hops = _received_hops(msg)
    text, html, attachments = _bodies(msg)

    report = Report(title=f"Phishing analysis - {path}")
    findings = report.findings

    # PHISH-001 authentication
    failed = {k: v for k, v in auth.items() if v not in ("pass", "bestguesspass")}
    if failed:
        sev = Severity.HIGH if auth.get("dmarc") == "fail" or auth.get("spf") == "fail" else Severity.MEDIUM
        findings.append(finding(
            "PHISH-001", sev, from_addr or "(no From)",
            "Authentication did not pass: " + ", ".join(f"{k.upper()}={v}" for k, v in failed.items())
            + ". The visible sender may be spoofed.",
            [str(h) for h in (msg.get_all("Authentication-Results") or [])][:3]))
    elif not auth:
        findings.append(finding("PHISH-001", Severity.LOW, from_addr or "(no From)",
                                "No Authentication-Results header - cannot confirm SPF/DKIM/DMARC."))

    # PHISH-002 path mismatches
    mismatches = []
    for rt in reply_to:
        if _domain_of(rt) and base_domain(_domain_of(rt)) != from_base:
            mismatches.append(f"Reply-To {rt} differs from From domain {from_dom}")
    if return_path and _domain_of(return_path) and base_domain(_domain_of(return_path)) != from_base:
        mismatches.append(f"Return-Path {return_path} differs from From domain {from_dom}")
    if mismatches:
        sev = Severity.HIGH if reply_to and any("Reply-To" in m for m in mismatches) else Severity.MEDIUM
        findings.append(finding("PHISH-002", sev, from_addr, "; ".join(mismatches) + ".", mismatches))

    # PHISH-003 impersonation
    look = brand_lookalike(from_dom) if from_dom else None
    if look:
        findings.append(finding("PHISH-003", Severity.HIGH, from_addr,
                                f"Sender domain {from_dom}: {look[1]}."))
    name_l = from_name.lower().replace(" ", "")
    for brand, legit in BRANDS.items():
        if brand in name_l and from_base not in legit and not look:
            findings.append(finding(
                "PHISH-003", Severity.HIGH, f"{from_name} <{from_addr}>",
                f"Display name claims '{brand}' but the address is on {from_dom or 'an unknown domain'}, "
                f"not {', '.join(legit)}."))
            break
    m = re.search(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", from_name)
    if m and _domain_of(m.group(0)) != from_dom:
        findings.append(finding("PHISH-003", Severity.HIGH, from_addr,
                                f"Display name contains a different address ({m.group(0)}) to look legitimate."))

    # PHISH-004 links
    parser = _LinkParser()
    if html:
        parser.feed(html)
    urls = {u.rstrip(".,;:!?'\")]") for u in URL.findall(text)}
    for href, _ in parser.links:
        if href.lower().startswith(("http://", "https://")):
            urls.add(href)
    url_rows = []
    for href, label in parser.links:
        if not href.lower().startswith(("http://", "https://")):
            continue
        shown = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", label, re.I)
        real = (urlsplit(href).hostname or "").lower()
        if shown and real and base_domain(shown.group(1).lower()) != base_domain(real):
            findings.append(finding(
                "PHISH-004", Severity.HIGH, defang(href),
                f"Link text shows '{label[:80]}' but points to {defang(real)} - deceptive link.",
                [f"text: {label[:120]}", f"href: {defang(href)}"], title="Deceptive link (text/target mismatch)"))
    for url in sorted(urls):
        reasons = _url_reasons(url, from_base)
        url_rows.append(defang(url))
        if reasons:
            sev = max(r[0] for r in reasons)
            findings.append(finding("PHISH-004", sev, defang(url),
                                    "; ".join(r[1] for r in reasons) + "."))
    for action in parser.forms:
        findings.append(finding("PHISH-004", Severity.HIGH, defang(action) or "(form)",
                                "Email body contains an HTML form - credential harvesting directly in mail.",
                                title="HTML form in email body"))

    # PHISH-005 attachments
    for att in attachments:
        name = att["name"].lower()
        exts = re.findall(r"\.([a-z0-9]{1,5})", name)
        last = exts[-1] if exts else ""
        reasons, sev = [], Severity.INFO
        if len(exts) >= 2 and last in EXEC_EXT | MACRO_EXT | HTML_EXT and exts[-2] in {
                "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "invoice"}:
            reasons.append(f"double extension (.{exts[-2]}.{last})")
            sev = Severity.CRITICAL
        if last in EXEC_EXT:
            reasons.append("executable / script")
            sev = max(sev, Severity.CRITICAL)
        elif last in MACRO_EXT:
            reasons.append("macro-enabled Office document")
            sev = max(sev, Severity.HIGH)
        elif last in HTML_EXT:
            reasons.append("HTML/SVG attachment - common for local credential-phishing pages")
            sev = max(sev, Severity.HIGH)
        elif last in CONTAINER_EXT:
            reasons.append("archive / disk image - used to bypass Mark-of-the-Web and scanners")
            sev = max(sev, Severity.MEDIUM)
        if re.search(r"[‮‏]", att["name"]):
            reasons.append("right-to-left override character in filename")
            sev = Severity.CRITICAL
        if reasons:
            findings.append(finding("PHISH-005", sev, att["name"],
                                    "; ".join(reasons) + f". SHA256 {att['sha256']}.",
                                    [f"{att['name']} {att['type']} {att['size']} bytes sha256={att['sha256']}"]))

    # PHISH-006 language
    blob = f"{subject}\n{text}\n{re.sub(r'<[^>]+>', ' ', html)}".lower()
    hits = sorted({kw for kw in URGENCY if kw in blob})
    if len(hits) >= 2:
        findings.append(finding("PHISH-006", Severity.MEDIUM if len(hits) >= 4 else Severity.LOW,
                                subject[:80] or "(no subject)",
                                f"Pressure phrases: {', '.join(hits)}."))

    score = min(100, sum(WEIGHTS[f.severity] for f in findings))
    verdict = ("LIKELY PHISHING" if score >= 50 else "SUSPICIOUS" if score >= 20 else "NO STRONG INDICATORS")

    s = Section("Verdict")
    s.add("Score", f"{score}/100")
    s.add("Verdict", verdict)
    report.sections.append(s)

    h = Section("Headers")
    h.add("Subject", subject)
    h.add("From", f"{from_name} <{from_addr}>" if from_name else from_addr)
    h.add("Reply-To", reply_to)
    h.add("Return-Path", return_path)
    h.add("Date", str(msg.get("Date", "")))
    h.add("Message-ID", str(msg.get("Message-ID", "")))
    h.add("SPF / DKIM / DMARC", " / ".join(auth.get(k, "none") for k in ("spf", "dkim", "dmarc")))
    origin = next((hop["ip"] for hop in hops if hop["ip"] and _is_public(hop["ip"])), "")
    h.add("Originating IP", origin)
    h.add("Received hops", len(hops))
    report.sections.append(h)

    if hops:
        r = Section("Delivery path (oldest first)")
        for i, hop in enumerate(hops, 1):
            r.add(f"hop {i}", f"{hop['from']} [{hop['ip'] or '?'}] -> {hop['by']}")
        report.sections.append(r)

    if url_rows:
        u = Section("URLs (defanged)")
        for i, url in enumerate(url_rows, 1):
            u.add(f"url {i}", url)
        report.sections.append(u)

    if attachments:
        a = Section("Attachments")
        for att in attachments:
            a.add(att["name"], f"{att['type']}, {att['size']} B, sha256={att['sha256']}")
        report.sections.append(a)

    block = Section("Block list (defanged)")
    domains = {from_dom} if from_dom and findings else set()
    bad_urls = sorted(u for u in urls if _url_reasons(u, from_base))
    # Never suggest blocking shared infrastructure (bit.ly, sharepoint.com...) - block the URL instead.
    domains |= {(urlsplit(u).hostname or "") for u in bad_urls
                if base_domain(urlsplit(u).hostname or "") not in SHORTENERS | FREE_HOSTING}
    block.add("Sender", from_addr if findings else "")
    block.add("URLs", [defang(u) for u in bad_urls])
    block.add("Domains", sorted(defang(d) for d in domains if d and not is_ip(d)))
    block.add("IPs", sorted(defang(ip) for ip in {d for d in domains if is_ip(d)}
                            | ({origin} if origin and findings else set())))
    block.add("Hashes", [att["sha256"] for att in attachments
                         if any(f.rule_id == "PHISH-005" and f.entity == att["name"] for f in findings)])
    if findings:
        report.sections.append(block)
    return report
