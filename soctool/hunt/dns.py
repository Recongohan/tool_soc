"""DNS hunting: tunneling, TXT abuse, DGA, rogue resolvers and fast flux.

Input: CSV or JSON Lines with (at least) ``src_ip`` and ``query``. Optional
columns make more rules work: ``timestamp``, ``qtype``, ``rcode``,
``resolver``, ``answers`` (``;``-separated) and ``ttl``. Zeek ``dns.log``
in JSON form is understood directly.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from soctool.core.logio import as_list, fmt_time, parse_time, read_records
from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.core.textutil import (base_domain, dga_score, is_public_ip, normalise_domain,
                                   shannon_entropy, subdomain_part)

ALIASES = {
    "ts": "timestamp", "time": "timestamp", "@timestamp": "timestamp",
    "id.orig_h": "src_ip", "src": "src_ip", "client_ip": "src_ip", "source_ip": "src_ip",
    "id.resp_h": "resolver", "server": "resolver", "dns_server": "resolver",
    "qtype_name": "qtype", "query_type": "qtype", "rcode_name": "rcode", "response_code": "rcode",
    "ttls": "ttl", "answer": "answers", "domain": "query", "qname": "query",
}

DEFAULTS: dict[str, float] = {
    "tunnel_min_queries": 10,      # suspicious queries per (host, domain) before alerting
    "tunnel_min_sub_len": 30,      # subdomain length that counts as "long"
    "tunnel_min_entropy": 3.5,     # bits/char of the subdomain
    "txt_min_queries": 20,
    "dga_min_nxdomain": 10,        # NXDOMAINs for random-looking names per host
    "dga_min_score": 0.5,
    "flux_min_ips": 8,
    "flux_min_nets": 5,            # distinct /16s
    "flux_max_ttl": 300,
}

# Large CDNs legitimately rotate many IPs; never flag them as fast flux.
FLUX_ALLOW = {
    "akamaiedge.net", "akamai.net", "akadns.net", "cloudfront.net", "amazonaws.com", "fastly.net",
    "cloudflare.com", "cloudflare.net", "googlevideo.com", "google.com", "googleapis.com",
    "gstatic.com", "microsoft.com", "windowsupdate.com", "azureedge.net", "trafficmanager.net",
    "apple.com", "icloud.com", "facebook.com", "fbcdn.net", "edgekey.net", "edgesuite.net",
}


@dataclass
class _TunnelAgg:
    count: int = 0
    total: int = 0
    sub_chars: int = 0
    entropy_sum: float = 0.0
    subdomains: set[str] = field(default_factory=set)
    qtypes: Counter = field(default_factory=Counter)
    samples: list[str] = field(default_factory=list)
    first: datetime | None = None
    last: datetime | None = None


def _touch(agg, ts: datetime | None) -> None:
    if ts is None:
        return
    if agg.first is None or ts < agg.first:
        agg.first = ts
    if agg.last is None or ts > agg.last:
        agg.last = ts


def hunt(path: str, cfg: dict[str, float] | None = None, allow: set[str] | None = None,
         internal_resolvers: set[str] | None = None) -> Report:
    cfg = {**DEFAULTS, **(cfg or {})}
    allow = {base_domain(a) for a in (allow or set())}
    internal_resolvers = internal_resolvers or set()

    rows = 0
    hosts: set[str] = set()
    tunnel: dict[tuple[str, str], _TunnelAgg] = defaultdict(_TunnelAgg)
    txt: dict[tuple[str, str], _TunnelAgg] = defaultdict(_TunnelAgg)
    nx_total: Counter = Counter()
    dga_nx: dict[str, _TunnelAgg] = defaultdict(_TunnelAgg)
    resolved_random: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    external: dict[str, _TunnelAgg] = defaultdict(_TunnelAgg)
    external_resolvers: dict[str, Counter] = defaultdict(Counter)
    flux_ips: dict[str, set[str]] = defaultdict(set)
    flux_ttl: dict[str, int] = {}
    flux_srcs: dict[str, set[str]] = defaultdict(set)

    for _, rec in read_records(path, ALIASES, required=("src_ip", "query")):
        query = normalise_domain(str(rec.get("query") or ""))
        src = str(rec.get("src_ip") or "").strip()
        if not query or not src:
            continue
        rows += 1
        hosts.add(src)
        ts = parse_time(rec.get("timestamp"))
        qtype = str(rec.get("qtype") or "").upper()
        rcode = str(rec.get("rcode") or "").upper()
        base = base_domain(query)
        if base in allow:
            continue
        sub = subdomain_part(query)
        key = (src, base)

        # DNS-001: long, high-entropy subdomains
        agg = tunnel[key]
        agg.total += 1
        flat = sub.replace(".", "")
        if len(flat) >= cfg["tunnel_min_sub_len"]:
            ent = shannon_entropy(flat)
            if ent >= cfg["tunnel_min_entropy"]:
                agg.count += 1
                agg.sub_chars += len(flat)
                agg.entropy_sum += ent
                agg.subdomains.add(sub)
                agg.qtypes[qtype or "?"] += 1
                if len(agg.samples) < 20:
                    agg.samples.append(f"{fmt_time(ts) or '-'} {qtype or '?':5} {query}")
                _touch(agg, ts)

        # DNS-002: TXT / NULL volume
        if qtype in ("TXT", "NULL"):
            t = txt[key]
            t.count += 1
            if len(t.samples) < 10:
                t.samples.append(f"{fmt_time(ts) or '-'} {qtype} {query}")
            _touch(t, ts)

        # DNS-003: NXDOMAIN for random-looking names
        score = dga_score(query)
        if rcode in ("NXDOMAIN", "3"):
            nx_total[src] += 1
            if score >= cfg["dga_min_score"]:
                d = dga_nx[src]
                d.count += 1
                d.subdomains.add(base)
                if len(d.samples) < 15:
                    d.samples.append(f"{fmt_time(ts) or '-'} NXDOMAIN {query} (dga_score={score})")
                _touch(d, ts)
        elif rcode in ("NOERROR", "0") and score >= cfg["dga_min_score"]:
            answers = [a for a in as_list(rec.get("answers")) if _is_ip(a)]
            resolved_random[src][query].update(answers or ["(no answer logged)"])

        # DNS-004: talking to a resolver that is not ours
        resolver = str(rec.get("resolver") or "").strip()
        if resolver:
            rogue = (resolver not in internal_resolvers) if internal_resolvers else is_public_ip(resolver)
            if rogue:
                e = external[src]
                e.count += 1
                external_resolvers[src][resolver] += 1
                if len(e.samples) < 10:
                    e.samples.append(f"{fmt_time(ts) or '-'} {src} -> {resolver} {qtype or '?'} {query}")
                _touch(e, ts)

        # DNS-005: answers spread across many networks
        answers = [a for a in as_list(rec.get("answers")) if _is_ip(a)]
        if answers and base not in FLUX_ALLOW:
            flux_ips[query].update(answers)
            flux_srcs[query].add(src)
            for ttl in as_list(rec.get("ttl")):
                try:
                    val = int(float(ttl))
                except ValueError:
                    continue
                flux_ttl[query] = min(val, flux_ttl.get(query, val))

    report = Report(title=f"DNS hunt - {path}")
    summary = Section("Summary")
    summary.add("Queries analysed", rows)
    summary.add("Unique source hosts", len(hosts))
    report.sections.append(summary)

    for (src, base), agg in tunnel.items():
        if agg.count < cfg["tunnel_min_queries"]:
            continue
        txt_agg = txt.pop((src, base), None)
        est_bytes = int(agg.sub_chars * 0.6)  # base32/base64/hex overhead ~ 0.5-0.75
        sev = Severity.CRITICAL if est_bytes >= 100_000 else Severity.HIGH
        qtypes = ", ".join(f"{k}={v}" for k, v in agg.qtypes.most_common())
        desc = (f"{agg.count} of {agg.total} queries to {base} carry long high-entropy subdomains "
                f"({len(agg.subdomains)} unique, avg {agg.sub_chars // agg.count} chars, "
                f"avg entropy {agg.entropy_sum / agg.count:.2f} bits/char; qtypes {qtypes}). "
                f"~{_human(est_bytes)} could have left the network this way.")
        if txt_agg:
            desc += f" Also {txt_agg.count} TXT/NULL queries to the same domain."
        desc += " Block the domain, isolate the host, check its EDR process tree for the DNS client."
        report.findings.append(finding("DNS-001", sev, f"{src} -> {base}", desc, agg.samples,
                                       fmt_time(agg.first), fmt_time(agg.last)))

    for (src, base), agg in txt.items():
        if agg.count < cfg["txt_min_queries"]:
            continue
        report.findings.append(finding(
            "DNS-002", Severity.MEDIUM, f"{src} -> {base}",
            f"{agg.count} TXT/NULL queries to {base}. Legitimate uses (SPF/DKIM lookups, some AV) exist; "
            f"check the process issuing them.", agg.samples, fmt_time(agg.first), fmt_time(agg.last)))

    for src, agg in dga_nx.items():
        if agg.count < cfg["dga_min_nxdomain"]:
            continue
        hits = resolved_random.get(src, {})
        sev = Severity.CRITICAL if hits else Severity.HIGH
        desc = (f"{agg.count} NXDOMAIN responses for random-looking domains "
                f"({len(agg.subdomains)} unique; {nx_total[src]} NXDOMAIN total from this host).")
        evidence = list(agg.samples)
        if hits:
            resolved = [f"RESOLVED {q} -> {', '.join(sorted(ips))}" for q, ips in sorted(hits.items())]
            desc += (f" {len(hits)} random-looking domain(s) DID resolve - likely the live C2 "
                     f"the operator registered: {', '.join(sorted(hits))}.")
            evidence = resolved + evidence
        desc += " Isolate the host and hunt the resolved IPs in proxy/firewall logs."
        report.findings.append(finding("DNS-003", sev, src, desc, evidence,
                                       fmt_time(agg.first), fmt_time(agg.last)))

    for src, agg in external.items():
        resolvers = ", ".join(f"{r} ({n})" for r, n in external_resolvers[src].most_common(5))
        report.findings.append(finding(
            "DNS-004", Severity.MEDIUM, src,
            f"{agg.count} queries sent directly to non-corporate resolver(s): {resolvers}. "
            f"Bypasses DNS logging/filtering; common for malware and tunneling tools. "
            f"Block outbound 53/853 except from corporate resolvers.",
            agg.samples, fmt_time(agg.first), fmt_time(agg.last)))

    for query, ips in flux_ips.items():
        nets = {_net16(ip) for ip in ips}
        ttl = flux_ttl.get(query)
        if len(ips) < cfg["flux_min_ips"] or len(nets) < cfg["flux_min_nets"]:
            continue
        if ttl is not None and ttl > cfg["flux_max_ttl"]:
            continue
        report.findings.append(finding(
            "DNS-005", Severity.MEDIUM, query,
            f"{query} resolved to {len(ips)} IPs across {len(nets)} unrelated /16 networks"
            f"{f' with TTL as low as {ttl}s' if ttl is not None else ''}; queried by "
            f"{len(flux_srcs[query])} host(s): {', '.join(sorted(flux_srcs[query])[:10])}.",
            [f"answer {ip}" for ip in sorted(ips)]))
    return report


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _net16(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    prefix = 16 if addr.version == 4 else 32
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
