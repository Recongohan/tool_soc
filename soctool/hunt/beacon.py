"""Beaconing detection over connection / proxy / firewall logs.

C2 implants "phone home" on a timer (e.g. every 60s +/- jitter). Humans do
not. For every (source, destination, port) we look at the gaps between
connections: a low coefficient of variation (stdev / mean) means a machine
is on a schedule.

Input: CSV / JSON Lines with ``timestamp``, ``src_ip``, ``dst`` and
optionally ``dst_port`` and ``bytes_out``. Zeek ``conn.log`` JSON works.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime

from soctool.core.logio import fmt_time, parse_time, read_records
from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.core.textutil import base_domain, is_ip

ALIASES = {
    "ts": "timestamp", "time": "timestamp", "@timestamp": "timestamp",
    "id.orig_h": "src_ip", "src": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip",
    "id.resp_h": "dst", "dst_ip": "dst", "dest": "dst", "dst_host": "dst", "host": "dst",
    "destination": "dst", "url_host": "dst",
    "id.resp_p": "dst_port", "port": "dst_port", "dest_port": "dst_port",
    "orig_bytes": "bytes_out", "bytes_sent": "bytes_out", "sent_bytes": "bytes_out", "bytes": "bytes_out",
}

DEFAULTS: dict[str, float] = {
    "min_connections": 20,     # fewer samples make the jitter estimate too noisy
    "min_interval_s": 5,       # ignore sub-5s chatter (streaming, keep-alives)
    "max_cv_high": 0.15,       # interval stdev/mean below this -> HIGH
    "max_cv_medium": 0.30,
}


def _trim(values: list[float], fraction: float = 0.1) -> list[float]:
    """Drop the top/bottom 10% so a few missed or retried beacons don't hide the pattern."""
    if len(values) < 10:
        return values
    k = int(len(values) * fraction)
    return sorted(values)[k:len(values) - k]


def hunt(path: str, cfg: dict[str, float] | None = None, allow: set[str] | None = None) -> Report:
    cfg = {**DEFAULTS, **(cfg or {})}
    allow = {a.lower() for a in (allow or set())}
    flows: dict[tuple[str, str, str], list[tuple[datetime, float | None]]] = defaultdict(list)
    rows = 0
    for _, rec in read_records(path, ALIASES, required=("timestamp", "src_ip", "dst")):
        ts = parse_time(rec.get("timestamp"))
        src = str(rec.get("src_ip") or "").strip()
        dst = str(rec.get("dst") or "").strip().lower()
        if ts is None or not src or not dst:
            continue
        if dst in allow or (not is_ip(dst) and base_domain(dst) in allow):
            continue
        rows += 1
        port = str(rec.get("dst_port") or "").strip()
        try:
            size = float(rec.get("bytes_out")) if rec.get("bytes_out") not in (None, "", "-") else None
        except (TypeError, ValueError):
            size = None
        flows[(src, dst, port)].append((ts, size))

    report = Report(title=f"Beacon hunt - {path}")
    s = Section("Summary")
    s.add("Connections analysed", rows)
    s.add("Unique src/dst/port flows", len(flows))
    report.sections.append(s)

    for (src, dst, port), conns in flows.items():
        if len(conns) < cfg["min_connections"]:
            continue
        conns.sort(key=lambda c: c[0])
        gaps = [(b[0] - a[0]).total_seconds() for a, b in zip(conns, conns[1:])]
        gaps = [g for g in gaps if g > 0]
        if len(gaps) < cfg["min_connections"] - 1:
            continue
        core = _trim(gaps)
        mean = statistics.fmean(core)
        if mean < cfg["min_interval_s"]:
            continue
        cv = statistics.pstdev(core) / mean
        # With few samples random traffic can look regular by chance: demand the strict bar.
        limit = cfg["max_cv_medium"] if len(conns) >= 30 else cfg["max_cv_high"]
        if cv > limit:
            continue
        sev = Severity.HIGH if cv <= cfg["max_cv_high"] else Severity.MEDIUM
        sizes = [c[1] for c in conns if c[1] is not None]
        size_note = ""
        if len(sizes) >= 5 and statistics.fmean(sizes) > 0:
            size_cv = statistics.pstdev(sizes) / statistics.fmean(sizes)
            size_note = f" Payload size is {'very consistent' if size_cv < 0.2 else 'variable'} " \
                        f"(avg {statistics.fmean(sizes):.0f} B, cv {size_cv:.2f})."
        duration_h = (conns[-1][0] - conns[0][0]).total_seconds() / 3600
        target = f"{dst}:{port}" if port else dst
        report.findings.append(finding(
            "NET-001", sev, f"{src} -> {target}",
            f"{len(conns)} connections over {duration_h:.1f} h, every {mean:.1f}s on average "
            f"(jitter cv={cv:.3f}; 0 = perfectly regular).{size_note} Check the destination's "
            f"reputation and which process on {src} owns the connection.",
            [f"{fmt_time(c[0])} {src} -> {target}" + (f" {c[1]:.0f}B" if c[1] is not None else "")
             for c in conns[:10]],
            fmt_time(conns[0][0]), fmt_time(conns[-1][0])))
    return report
