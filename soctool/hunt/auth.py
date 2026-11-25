"""Authentication log hunting: brute force, password spraying, impossible travel.

Input: CSV / JSON Lines with ``timestamp``, ``user``, ``src_ip`` and
``result`` (success/failure - many spellings understood). Optional
``country`` enables impossible-travel detection; ``service`` is shown in
evidence. Works for Windows 4624/4625 exports, VPN, SSO, SSH, O365 sign-ins.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

from soctool.core.logio import fmt_time, max_in_window, parse_time, read_records
from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.core.textutil import is_public_ip

ALIASES = {
    "ts": "timestamp", "time": "timestamp", "@timestamp": "timestamp", "timecreated": "timestamp",
    "username": "user", "account": "user", "targetusername": "user", "userprincipalname": "user",
    "src": "src_ip", "source_ip": "src_ip", "ipaddress": "src_ip", "client_ip": "src_ip", "ip": "src_ip",
    "status": "result", "outcome": "result", "event_outcome": "result", "eventid": "result",
    "location": "country", "country_code": "country", "app": "service", "logon_type": "service",
}

SUCCESS = {"success", "succeeded", "ok", "true", "allow", "allowed", "accepted", "4624", "0", "pass", "passed"}
FAILURE = {"failure", "failed", "fail", "false", "deny", "denied", "rejected", "invalid", "4625", "4771",
           "4776", "50126", "bad_password", "error"}

DEFAULTS: dict[str, float] = {
    "brute_min_fail": 10,
    "brute_window_s": 600,
    "spray_min_users": 10,
    "spray_window_s": 3600,
    "travel_max_hours": 2,
}


@dataclass
class _Event:
    ts: datetime
    user: str
    ip: str
    ok: bool
    country: str
    service: str

    def line(self) -> str:
        where = f" [{self.country}]" if self.country else ""
        svc = f" {self.service}" if self.service else ""
        return f"{fmt_time(self.ts)} {self.user} from {self.ip}{where}{svc} -> {'SUCCESS' if self.ok else 'FAIL'}"


def _outcome(value: str) -> bool | None:
    v = value.strip().lower()
    if v in SUCCESS:
        return True
    if v in FAILURE:
        return False
    return None


def hunt(path: str, cfg: dict[str, float] | None = None, allow: set[str] | None = None) -> Report:
    cfg = {**DEFAULTS, **(cfg or {})}
    allow = allow or set()
    events: list[_Event] = []
    skipped = 0
    for _, rec in read_records(path, ALIASES, required=("timestamp", "user", "src_ip", "result")):
        ts = parse_time(rec.get("timestamp"))
        ok = _outcome(str(rec.get("result") or ""))
        user = str(rec.get("user") or "").strip().lower()
        ip = str(rec.get("src_ip") or "").strip()
        if ts is None or ok is None or not user or ip in allow:
            skipped += 1
            continue
        events.append(_Event(ts, user, ip, ok, str(rec.get("country") or "").strip().upper(),
                             str(rec.get("service") or "").strip()))
    events.sort(key=lambda e: e.ts)

    report = Report(title=f"Authentication hunt - {path}")
    s = Section("Summary")
    s.add("Events analysed", len(events))
    s.add("Skipped (unparseable)", skipped)
    s.add("Failures", sum(1 for e in events if not e.ok))
    s.add("Unique accounts", len({e.user for e in events}))
    s.add("Unique sources", len({e.ip for e in events}))
    report.sections.append(s)

    by_user_ip: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    by_ip: dict[str, list[_Event]] = defaultdict(list)
    by_user: dict[str, list[_Event]] = defaultdict(list)
    for e in events:
        by_user_ip[(e.user, e.ip)].append(e)
        by_ip[e.ip].append(e)
        by_user[e.user].append(e)

    # AUTH-001 brute force: one account, one source, many failures
    for (user, ip), evs in by_user_ip.items():
        fails = [e for e in evs if not e.ok]
        times = [e.ts for e in fails]
        count, lo, hi = max_in_window(times, cfg["brute_window_s"])
        if count < cfg["brute_min_fail"]:
            continue
        start, end = times[lo], times[hi]
        success = [e for e in evs if e.ok and e.ts >= start
                   and (e.ts - end).total_seconds() <= cfg["brute_window_s"]]
        sev = Severity.CRITICAL if success else (Severity.HIGH if is_public_ip(ip) else Severity.MEDIUM)
        desc = f"{count} failed logins for '{user}' from {ip} within {int(cfg['brute_window_s'] // 60)} min."
        evidence = [e.line() for e in fails[lo:hi + 1][:10]]
        if success:
            desc += (f" Then SUCCEEDED at {fmt_time(success[0].ts)} - treat the account as compromised: "
                     f"disable/reset, revoke sessions and tokens, review activity after login.")
            evidence = [f"SUCCESS {e.line()}" for e in success[:3]] + evidence
        report.findings.append(finding("AUTH-001", sev, f"{user} <- {ip}", desc, evidence,
                                       fmt_time(start), fmt_time(end)))

    # AUTH-002 spraying: one source, failures across many accounts
    for ip, evs in by_ip.items():
        fails = [e for e in evs if not e.ok]
        if len({e.user for e in fails}) < cfg["spray_min_users"]:
            continue
        best_users: set[str] = set()
        best = (0, 0, 0)
        left = 0
        window: Counter = Counter()
        for right, e in enumerate(fails):
            window[e.user] += 1
            while (e.ts - fails[left].ts).total_seconds() > cfg["spray_window_s"]:
                window[fails[left].user] -= 1
                if not window[fails[left].user]:
                    del window[fails[left].user]
                left += 1
            if len(window) > best[0]:
                best = (len(window), left, right)
                best_users = set(window)
        if best[0] < cfg["spray_min_users"]:
            continue
        start, end = fails[best[1]].ts, fails[best[2]].ts
        compromised = sorted({e.user for e in evs if e.ok and e.ts >= start and e.user in best_users})
        sev = Severity.CRITICAL if compromised else Severity.HIGH
        desc = (f"{ip} failed logins against {best[0]} different accounts within "
                f"{int(cfg['spray_window_s'] // 60)} min (avg {(best[2] - best[1] + 1) / best[0]:.1f} "
                f"attempts per account - low-and-slow to dodge lockout).")
        evidence = [e.line() for e in fails[best[1]:best[2] + 1][:10]]
        if compromised:
            desc += f" Successful login afterwards for: {', '.join(compromised)}. Reset those accounts now."
            evidence = [f"SUCCESS {e.line()}" for e in evs if e.ok and e.user in compromised][:5] + evidence
        desc += " Block the source and check for the same password pattern across the tenant."
        report.findings.append(finding("AUTH-002", sev, ip, desc, evidence, fmt_time(start), fmt_time(end)))

    # AUTH-003 impossible travel: successful logins, different countries, too close in time
    for user, evs in by_user.items():
        # Internal logins carry no real geolocation, so only public sources count.
        ok = [e for e in evs if e.ok and e.country and is_public_ip(e.ip)]
        for a, b in zip(ok, ok[1:]):
            if a.country == b.country:
                continue
            hours = (b.ts - a.ts).total_seconds() / 3600
            if hours > cfg["travel_max_hours"]:
                continue
            report.findings.append(finding(
                "AUTH-003", Severity.HIGH, user,
                f"Successful logins from {a.country} ({a.ip}) and {b.country} ({b.ip}) "
                f"{hours * 60:.0f} minutes apart. Rule out VPN/egress changes, then treat as session "
                f"or credential theft.",
                [a.line(), b.line()], fmt_time(a.ts), fmt_time(b.ts)))
    return report
