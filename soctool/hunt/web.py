"""Web server log hunting (Apache / Nginx combined log format).

Rules: 404 bursts (content discovery), scanner user agents, web shells,
injection payloads, login brute force and sensitive file exposure.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote_plus

from soctool.core.logio import fmt_time, max_in_window, open_text, parse_time
from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

DEFAULTS: dict[str, float] = {
    "scan_min_404": 20,          # 404s from one IP inside the window
    "scan_window_s": 300,
    "brute_min_fail": 10,        # failed logins from one IP inside the window
    "brute_window_s": 600,
}

ATTACK_TOOLS = {
    "sqlmap": "sqlmap", "nikto": "Nikto", "nmap": "Nmap", "masscan": "masscan", "zgrab": "zgrab",
    "gobuster": "gobuster", "dirbuster": "DirBuster", "dirb/": "dirb", "wfuzz": "wfuzz", "ffuf": "ffuf",
    "feroxbuster": "feroxbuster", "nuclei": "Nuclei", "acunetix": "Acunetix", "nessus": "Nessus",
    "openvas": "OpenVAS", "w3af": "w3af", "wpscan": "WPScan", "hydra": "Hydra", "havij": "Havij",
    "commix": "commix", "xsstrike": "XSStrike", "jaeles": "Jaeles", "arachni": "Arachni",
}
SCRIPT_CLIENTS = {
    "python-requests": "python-requests", "python-urllib": "python-urllib", "curl/": "curl",
    "wget/": "wget", "go-http-client": "Go http client", "libwww-perl": "libwww-perl",
    "okhttp": "okhttp", "java/": "Java", "scrapy": "Scrapy", "powershell": "PowerShell",
    "httpclient": "HttpClient", "aiohttp": "aiohttp", "axios": "axios",
}

SCRIPT_EXT = re.compile(r"\.(php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|asmx|cgi|pl)$", re.I)
STATIC_DIRS = re.compile(r"/(images?|img|uploads?|upload_files|files|static|assets|css|js|media|"
                         r"wp-content/uploads|tmp|temp|cache|fonts)/", re.I)
SHELL_NAMES = re.compile(r"/(shell|cmd|c99|r57|wso|b374k|alfa|webshell|backdoor|up|x|1|test1|"
                         r"phpspy|aspxspy|chopper|china|indoxploit)\.(php\d?|aspx?|jspx?)$", re.I)
SHELL_PARAMS = re.compile(r"[?&](cmd|exec|command|execute|c|e|pass|code)=", re.I)

INJECTION = [
    ("SQLi", re.compile(r"union(\s|/\*.*?\*/|\+)+(all(\s|\+)+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d+|"
                        r"\bsleep\(\s*\d+\s*\)|benchmark\(|information_schema|waitfor\s+delay|"
                        r"\bselect\b.+\bfrom\b.+\bwhere\b|extractvalue\(|updatexml\(", re.I)),
    ("XSS", re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg[^>]*on\w+=|"
                       r"alert\s*\(|document\.cookie", re.I)),
    ("Path traversal / LFI", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|"
                                        r"php://|file://|/proc/self/environ", re.I)),
    ("Command injection", re.compile(r"[;|`&]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|"
                                     r"powershell|cmd(\.exe)?)\b|\$\([^)]*\)", re.I)),
    ("Log4Shell / JNDI", re.compile(r"\$\{\s*(jndi|\$\{lower|\$\{::-j)", re.I)),
    ("SSRF / metadata", re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.I)),
]

LOGIN_PATH = re.compile(r"/(login|signin|sign-in|logon|wp-login\.php|auth|authenticate|session|"
                        r"api/(v\d/)?(auth|login|token)|user/login|admin/login|xmlrpc\.php)\b", re.I)
SENSITIVE = re.compile(r"/(\.env|\.git/(config|HEAD)|\.svn/|\.htpasswd|\.aws/credentials|\.ssh/|"
                       r"wp-config\.php(\.bak|~|\.old|\.save)?|config\.php\.(bak|old)|web\.config|"
                       r"phpinfo\.php|server-status|backup\.(zip|tar\.gz|sql)|dump\.sql|database\.sql|"
                       r"\.DS_Store|id_rsa)(\?|$)", re.I)


@dataclass
class _Req:
    ts: datetime | None
    ip: str
    method: str
    path: str
    status: int
    ua: str

    def line(self) -> str:
        return f"{fmt_time(self.ts) or '-'} {self.ip} {self.method} {self.path} -> {self.status}"


@dataclass
class _Group:
    reqs: list[_Req] = field(default_factory=list)
    tags: Counter = field(default_factory=Counter)


def parse_line(line: str) -> _Req | None:
    m = LINE_RE.match(line)
    if not m:
        return None
    parts = m.group("request").split()
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", m.group("request") or "-")
    return _Req(parse_time(m.group("time")), m.group("ip"), method.upper(), path,
                int(m.group("status")), m.group("ua") or "")


def hunt(path: str, cfg: dict[str, float] | None = None, allow: set[str] | None = None) -> Report:
    cfg = {**DEFAULTS, **(cfg or {})}
    allow = allow or set()
    total = unparsed = 0
    ips: set[str] = set()
    not_found: dict[str, list[_Req]] = defaultdict(list)
    tools: dict[tuple[str, str, Severity], _Group] = defaultdict(_Group)
    shells: dict[str, _Group] = defaultdict(_Group)
    injections: dict[str, _Group] = defaultdict(_Group)
    logins: dict[str, list[_Req]] = defaultdict(list)
    exposed: dict[str, _Group] = defaultdict(_Group)

    with open_text(path) as fh:
        for raw in fh:
            if not raw.strip():
                continue
            total += 1
            req = parse_line(raw.rstrip("\n"))
            if req is None:
                unparsed += 1
                continue
            if req.ip in allow:
                continue
            ips.add(req.ip)
            path_only = req.path.split("?", 1)[0]
            decoded = unquote_plus(unquote_plus(req.path))
            ua_l = req.ua.lower()

            if req.status == 404:
                not_found[req.ip].append(req)

            for needle, name in ATTACK_TOOLS.items():
                if needle in ua_l:
                    tools[(req.ip, name, Severity.HIGH)].reqs.append(req)
                    break
            else:
                for needle, name in SCRIPT_CLIENTS.items():
                    if needle in ua_l:
                        tools[(req.ip, name, Severity.LOW)].reqs.append(req)
                        break

            if SCRIPT_EXT.search(path_only):
                in_static = bool(STATIC_DIRS.search(path_only))
                known = bool(SHELL_NAMES.search(path_only))
                cmd_param = bool(SHELL_PARAMS.search(req.path))
                if (req.method == "POST" and (in_static or known)) or (known and cmd_param) \
                        or (in_static and cmd_param):
                    g = shells[path_only]
                    g.reqs.append(req)
                    if in_static:
                        g.tags["script in static/upload dir"] += 1
                    if known:
                        g.tags["known web shell filename"] += 1
                    if cmd_param:
                        g.tags["command parameter in query"] += 1

            haystack = f"{decoded} {req.ua} "
            for label, rx in INJECTION:
                if rx.search(haystack):
                    g = injections[req.ip]
                    g.reqs.append(req)
                    g.tags[label] += 1

            if LOGIN_PATH.search(path_only):
                logins[req.ip].append(req)

            if req.status == 200 and SENSITIVE.search(req.path):
                exposed[req.ip].reqs.append(req)

    report = Report(title=f"Web log hunt - {path}")
    s = Section("Summary")
    s.add("Lines read", total)
    s.add("Unparsed lines", unparsed)
    s.add("Unique client IPs", len(ips))
    report.sections.append(s)

    for ip, reqs in not_found.items():
        times = sorted(r.ts for r in reqs if r.ts)
        count, lo, hi = max_in_window(times, cfg["scan_window_s"]) if times else (len(reqs), 0, 0)
        if count < cfg["scan_min_404"]:
            continue
        paths = {r.path for r in reqs}
        later_hits = exposed.get(ip)
        sev = Severity.HIGH if later_hits else Severity.MEDIUM
        desc = (f"{count} 404s within {int(cfg['scan_window_s'])}s ({len(reqs)} total, "
                f"{len(paths)} distinct paths). Content discovery / wordlist scanning.")
        if later_hits:
            desc += f" The same client then retrieved {len(later_hits.reqs)} sensitive file(s) - see WEB-006."
        report.findings.append(finding("WEB-001", sev, ip, desc, [r.line() for r in reqs[:20]],
                                       fmt_time(times[lo]) if times else None,
                                       fmt_time(times[hi]) if times else None))

    for (ip, tool, sev), g in tools.items():
        kind = "attack tool" if sev == Severity.HIGH else "scripting client (not a browser)"
        statuses = Counter(r.status for r in g.reqs)
        report.findings.append(finding(
            "WEB-002", sev, ip,
            f"{len(g.reqs)} requests with {tool} user agent ({kind}). Status codes: "
            f"{', '.join(f'{k}x{v}' for k, v in statuses.most_common())}. UA: {g.reqs[0].ua[:120]}",
            [r.line() for r in g.reqs[:10]], *_span(g.reqs)))

    for p, g in shells.items():
        clients = Counter(r.ip for r in g.reqs)
        ok = sum(1 for r in g.reqs if r.status == 200)
        sev = Severity.CRITICAL if ok else Severity.HIGH
        report.findings.append(finding(
            "WEB-003", sev, p,
            f"{len(g.reqs)} suspicious requests ({ok} returned 200) from "
            f"{', '.join(f'{ip} ({n})' for ip, n in clients.most_common(5))}. "
            f"Indicators: {', '.join(g.tags)}. Pull the file from disk, check its creation time "
            f"and the upload request that dropped it.",
            [r.line() for r in g.reqs[:15]], *_span(g.reqs)))

    for ip, g in injections.items():
        ok = sum(1 for r in g.reqs if r.status == 200)
        report.findings.append(finding(
            "WEB-004", Severity.HIGH, ip,
            f"{len(g.reqs)} requests with exploit payloads: "
            f"{', '.join(f'{k} x{v}' for k, v in g.tags.most_common())}. "
            f"{ok} got HTTP 200 - verify whether any succeeded (response size, app/DB logs).",
            [unquote_plus(r.line())[:300] for r in g.reqs[:15]], *_span(g.reqs)))

    for ip, reqs in logins.items():
        reqs.sort(key=lambda r: r.ts.timestamp() if r.ts else 0.0)
        fails = [r for r in reqs if r.status in (401, 403)]
        times = [r.ts for r in fails if r.ts]
        count, lo, hi = max_in_window(times, cfg["brute_window_s"]) if times else (len(fails), 0, 0)
        if count < cfg["brute_min_fail"]:
            continue
        burst_start = times[lo] if times else None
        success = [r for r in reqs if r.status in (200, 302) and r.method == "POST"
                   and (burst_start is None or (r.ts and r.ts >= burst_start))]
        sev = Severity.CRITICAL if success else Severity.MEDIUM
        desc = f"{count} failed login requests (401/403) within {int(cfg['brute_window_s'])}s."
        evidence = [r.line() for r in fails[:10]]
        if success:
            desc += (f" Followed by {len(success)} successful POST(s) - credentials were likely guessed. "
                     f"Identify the account, reset it and review the session.")
            evidence = [f"SUCCESS {r.line()}" for r in success[:5]] + evidence
        report.findings.append(finding("WEB-005", sev, ip, desc, evidence,
                                       fmt_time(burst_start), fmt_time(times[hi]) if times else None))

    for ip, g in exposed.items():
        report.findings.append(finding(
            "WEB-006", Severity.HIGH, ip,
            f"{len(g.reqs)} sensitive file(s) served with HTTP 200: "
            f"{', '.join(sorted({r.path for r in g.reqs}))}. Assume any secrets inside are compromised; "
            f"rotate them and block the path.",
            [r.line() for r in g.reqs], *_span(g.reqs)))
    return report


def _span(reqs: list[_Req]) -> tuple[str | None, str | None]:
    times = [r.ts for r in reqs if r.ts]
    if not times:
        return None, None
    return fmt_time(min(times)), fmt_time(max(times))
