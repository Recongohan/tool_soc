"""IOC enrichment: offline heuristics, plus optional VirusTotal / AbuseIPDB lookups.

Online lookups are opt-in (``--online``) and only run for providers whose
API key is set in the environment:

    VT_API_KEY         https://www.virustotal.com/gui/my-apikey
    ABUSEIPDB_API_KEY  https://www.abuseipdb.com/account/api

Never send internal indicators (private IPs, internal hostnames) to third
parties - they are skipped automatically.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.core.textutil import (SUSPICIOUS_TLDS, base_domain, brand_lookalike, dga_score,
                                   shannon_entropy, subdomain_part, tld)
from soctool.ioc.extract import classify, defang, refang

TIMEOUT = 15
Fetcher = Callable[[str, dict[str, str]], Any]


def _http_get_json(url: str, headers: dict[str, str]) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "soctool", **headers})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed https endpoints
        return json.loads(resp.read().decode("utf-8"))


def offline(value: str, kind: str, section: Section, report: Report) -> None:
    if kind == "ip":
        addr = ipaddress.ip_address(value)
        scope = ("private (RFC1918)" if addr.is_private and not addr.is_loopback else
                 "loopback" if addr.is_loopback else
                 "link-local" if addr.is_link_local else
                 "multicast" if addr.is_multicast else
                 "reserved" if addr.is_reserved else
                 "public" if addr.is_global else "special-purpose")
        section.add("IP version", f"IPv{addr.version}")
        section.add("Scope", scope)
        if not addr.is_global:
            section.add("Note", "Internal/non-routable: pivot in your own logs (DHCP, EDR, asset inventory).")
    elif kind in ("domain", "url", "email"):
        if kind == "url":
            host = urllib.parse.urlsplit(value).hostname or ""
            section.add("Host", host)
            parsed = urllib.parse.urlsplit(value)
            section.add("Path", parsed.path or "/")
            if parsed.username or "@" in parsed.netloc:
                section.add("Warning", "URL contains '@' userinfo - the real host is after the '@'.")
        elif kind == "email":
            host = value.split("@", 1)[1]
            section.add("Mail domain", host)
        else:
            host = value
        host = host.lower()
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            section.add("Note", "Host is a raw IP address - unusual for legitimate links.")
            return
        except ValueError:
            pass
        sub = subdomain_part(host)
        score = dga_score(host)
        look = brand_lookalike(host)
        section.add("Registrable domain", base_domain(host))
        section.add("TLD", tld(host) + ("  (high-abuse TLD)" if tld(host) in SUSPICIOUS_TLDS else ""))
        section.add("Subdomain", sub or "-")
        section.add("Label entropy", f"{shannon_entropy(base_domain(host).split('.')[0]):.2f} bits/char")
        section.add("DGA score", f"{score} (0-1, >=0.5 looks machine-generated)")
        if "xn--" in host:
            section.add("Punycode", "yes - may render as a lookalike with non-Latin characters")
        if look:
            section.add("Brand lookalike", look[1])
        reasons = []
        if score >= 0.5:
            reasons.append(f"DGA-like (score {score})")
        if look:
            reasons.append(look[1])
        if "xn--" in host:
            reasons.append("punycode / IDN")
        if tld(host) in SUSPICIOUS_TLDS:
            reasons.append(f"high-abuse TLD .{tld(host)}")
        if len(sub) > 40:
            reasons.append("very long subdomain")
        if reasons:
            sev = Severity.HIGH if (look or score >= 0.7) else Severity.MEDIUM if len(reasons) > 1 else Severity.LOW
            report.findings.append(finding("IOC-001", sev, defang(value), "; ".join(reasons) + "."))
    elif kind in ("md5", "sha1", "sha256"):
        section.add("Hash type", kind.upper())
        section.add("Pivot", "Search EDR for the hash; check VirusTotal / MalwareBazaar.")
    elif kind == "cve":
        section.add("Reference", f"https://nvd.nist.gov/vuln/detail/{value.upper()}")
        section.add("KEV check", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")


def virustotal(value: str, kind: str, key: str, fetch: Fetcher) -> dict[str, Any]:
    if kind == "ip":
        path = f"ip_addresses/{value}"
    elif kind == "domain":
        path = f"domains/{value}"
    elif kind == "url":
        path = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    elif kind in ("md5", "sha1", "sha256"):
        path = f"files/{value}"
    else:
        return {}
    data = fetch(f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": key})
    attrs = (data or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    out = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
    }
    for extra in ("as_owner", "country", "meaningful_name", "type_description", "registrar", "creation_date"):
        if attrs.get(extra) is not None:
            out[extra] = attrs[extra]
    return out


def abuseipdb(value: str, key: str, fetch: Fetcher) -> dict[str, Any]:
    q = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
    data = fetch(f"https://api.abuseipdb.com/api/v2/check?{q}", {"Key": key, "Accept": "application/json"})
    d = (data or {}).get("data", {})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "is_tor": d.get("isTor"),
    }


def enrich(values: list[str], online: bool = False, fetch: Fetcher = _http_get_json) -> Report:
    report = Report(title="IOC enrichment")
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if online and not (vt_key or abuse_key):
        note = Section("Online lookups")
        note.add("Status", "skipped - set VT_API_KEY and/or ABUSEIPDB_API_KEY to enable")
        report.sections.append(note)

    for raw in values:
        value = refang(raw.strip())
        if not value:
            continue
        kind = classify(value)
        if kind in ("md5", "sha1", "sha256", "domain"):
            value = value.lower()
        section = Section(f"{defang(value)}")
        section.add("Type", kind)
        report.sections.append(section)
        if kind == "unknown":
            section.add("Note", "Not recognised as an IP, domain, URL, email, hash or CVE.")
            continue
        offline(value, kind, section, report)

        if not online:
            continue
        internal = (kind == "ip" and not ipaddress.ip_address(value).is_global)
        if internal:
            section.add("Online", "skipped - non-public IP is never sent to third parties")
            continue
        if vt_key and kind in ("ip", "domain", "url", "md5", "sha1", "sha256"):
            try:
                vt = virustotal(value, kind, vt_key, fetch)
                section.add("VirusTotal", ", ".join(f"{k}={v}" for k, v in vt.items()))
                if vt.get("malicious", 0) >= 3:
                    sev = Severity.CRITICAL if vt["malicious"] >= 10 else Severity.HIGH
                    report.findings.append(finding(
                        "IOC-002", sev, defang(value),
                        f"VirusTotal: {vt['malicious']} engines flag this {kind} as malicious "
                        f"({vt.get('suspicious', 0)} suspicious)."))
                elif vt.get("malicious", 0) > 0:
                    report.findings.append(finding(
                        "IOC-002", Severity.MEDIUM, defang(value),
                        f"VirusTotal: {vt['malicious']} engine(s) flag this {kind} - low consensus, verify."))
            except urllib.error.HTTPError as exc:
                section.add("VirusTotal", "not found" if exc.code == 404 else f"error HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                section.add("VirusTotal", f"error: {exc}")
        if abuse_key and kind == "ip":
            try:
                ab = abuseipdb(value, abuse_key, fetch)
                section.add("AbuseIPDB", ", ".join(f"{k}={v}" for k, v in ab.items()))
                score = ab.get("abuse_confidence") or 0
                if score >= 50:
                    report.findings.append(finding(
                        "IOC-002", Severity.HIGH if score >= 80 else Severity.MEDIUM, defang(value),
                        f"AbuseIPDB confidence {score}% from {ab.get('total_reports')} reports "
                        f"({ab.get('isp')}, {ab.get('country')})."))
            except urllib.error.HTTPError as exc:
                section.add("AbuseIPDB", f"error HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                section.add("AbuseIPDB", f"error: {exc}")
    return report
