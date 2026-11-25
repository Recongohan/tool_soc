"""Command-line entry point: ``soc <command> ...``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from soctool import __version__
from soctool.core.logio import LogFormatError
from soctool.core.models import Report, Severity
from soctool.core.render import FORMATS, render
from soctool.core.rules import RULES, technique_name

HUNTERS = ("dns", "web", "auth", "beacon")
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _parse_set(values: list[str] | None) -> dict[str, float]:
    out: dict[str, float] = {}
    for item in values or []:
        if "=" not in item:
            raise SystemExit(f"--set expects key=value, got {item!r}")
        key, val = item.split("=", 1)
        try:
            out[key.strip()] = float(val)
        except ValueError:
            raise SystemExit(f"--set {key}: value must be a number") from None
    return out


def _read_list(path: str | None) -> set[str]:
    if not path:
        return set()
    with open(path, encoding="utf-8") as fh:
        return {ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")}


def run_hunt(kind: str, path: str, settings: dict[str, float] | None = None,
             allow: set[str] | None = None, resolvers: set[str] | None = None) -> Report:
    if kind == "dns":
        from soctool.hunt import dns
        return dns.hunt(path, settings, allow, resolvers)
    if kind == "web":
        from soctool.hunt import web
        return web.hunt(path, settings, allow)
    if kind == "auth":
        from soctool.hunt import auth
        return auth.hunt(path, settings, allow)
    if kind == "beacon":
        from soctool.hunt import beacon
        return beacon.hunt(path, settings, allow)
    raise ValueError(f"unknown hunter {kind}")


def hunter_defaults(kind: str) -> dict[str, float]:
    from soctool.hunt import auth, beacon, dns, web
    return {"dns": dns.DEFAULTS, "web": web.DEFAULTS, "auth": auth.DEFAULTS, "beacon": beacon.DEFAULTS}[kind]


def _emit(report: Report, args: argparse.Namespace) -> int:
    min_sev = Severity.parse(args.min_severity)
    colour = False if args.no_color else None
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            render(report, args.format, fh, min_sev, colour=False)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        render(report, args.format, sys.stdout, min_sev, colour=colour)
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in report.findings):
            return 2
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    report = run_hunt(args.kind, args.file, _parse_set(args.set), _read_list(args.allowlist),
                      set(args.resolver or []))
    return _emit(report, args)


def cmd_ioc(args: argparse.Namespace) -> int:
    from soctool.ioc.extract import defang, extract, refang
    if args.action in ("defang", "refang"):
        values = args.values or [ln.rstrip("\n") for ln in sys.stdin]
        fn = defang if args.action == "defang" else refang
        for v in values:
            print(fn(v))
        return 0
    if args.action == "extract":
        text = _read_inputs(args.values)
        iocs = extract(text, include_private=args.include_private)
        from soctool.core.models import Section
        report = Report(title="IOC extraction")
        for kind, vals in iocs.items():
            if vals:
                report.sections.append(Section(f"{kind} ({len(vals)})",
                                               [(str(i), defang(v) if not args.raw else v)
                                                for i, v in enumerate(vals, 1)]))
        if args.format == "text" and not iocs.total():
            print("No indicators found.")
            return 0
        if args.format == "text" and args.plain:
            for _, vals in iocs.items():
                for v in vals:
                    print(v if args.raw else defang(v))
            return 0
        return _emit(report, args)
    # enrich
    from soctool.ioc.enrich import enrich
    values = list(args.values)
    if args.file:
        values += [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.startswith("#")]
    if not values:
        values = [ln.strip() for ln in sys.stdin if ln.strip()]
    return _emit(enrich(values, online=args.online), args)


def _read_inputs(values: list[str]) -> str:
    if not values or values == ["-"]:
        return sys.stdin.read()
    chunks = []
    for v in values:
        if os.path.isfile(v):
            chunks.append(Path(v).read_text(encoding="utf-8", errors="replace"))
        else:
            chunks.append(v)
    return "\n".join(chunks)


def cmd_decode(args: argparse.Namespace) -> int:
    from soctool.ioc.decode import decode_report
    data = " ".join(args.data) if args.data else sys.stdin.read()
    return _emit(decode_report(data), args)


def cmd_phish(args: argparse.Namespace) -> int:
    from soctool.phish.analyzer import analyze
    return _emit(analyze(args.file), args)


def cmd_rules(args: argparse.Namespace) -> int:
    for rule in RULES.values():
        print(f"{rule.rule_id:10} {rule.title}")
        print(f"{'':10} {rule.description}")
        print(f"{'':10} MITRE: " + "; ".join(f"{t} {technique_name(t)}" for t in rule.mitre) + "\n")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    samples = Path(args.samples)
    jobs = [("dns", "dns.csv"), ("web", "access.log"), ("auth", "auth.csv"), ("beacon", "conn.csv")]
    rc = 0
    for kind, name in jobs:
        path = samples / name
        if not path.exists():
            print(f"missing {path} - run: python samples/generate.py", file=sys.stderr)
            return 1
        rc = max(rc, _emit(run_hunt(kind, str(path)), args))
        print()
    from soctool.phish.analyzer import analyze
    rc = max(rc, _emit(analyze(str(samples / "phish.eml")), args))
    return rc


def cmd_web(args: argparse.Namespace) -> int:
    from soctool.web.server import serve
    serve(args.host, args.port, open_browser=not args.no_browser)
    return 0


def _add_output(p: argparse.ArgumentParser) -> None:
    p.add_argument("-f", "--format", choices=FORMATS, default="text", help="output format (default: text)")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--min-severity", default="info", metavar="SEV",
                   help="hide findings below this severity (info|low|medium|high|critical)")
    p.add_argument("--fail-on", metavar="SEV", help="exit with code 2 if any finding >= SEV (for automation)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc",
        description="SOC analyst toolkit: hunt through logs, triage phishing, enrich and decode IOCs.",
        epilog="Examples:\n"
               "  soc hunt dns samples/dns.csv\n"
               "  soc hunt web /var/log/nginx/access.log --min-severity high\n"
               "  soc phish suspicious.eml -f markdown -o ticket.md\n"
               "  soc ioc enrich 45.33.32.156 paypa1-secure.com --online\n"
               "  soc decode \"powershell -enc SQBFAFgA...\"\n"
               "  soc web            # open the browser UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"soctool {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p = sub.add_parser("hunt", help="run detections over a log file",
                       description="Run detections over a log file (CSV, JSON Lines or web access log).")
    p.add_argument("kind", choices=HUNTERS, help="log type: dns | web | auth | beacon")
    p.add_argument("file", help="log file path, or - for stdin")
    p.add_argument("--set", action="append", metavar="KEY=VALUE",
                   help="override a threshold, e.g. --set tunnel_min_queries=5 (see README)")
    p.add_argument("--allowlist", metavar="FILE", help="file of domains/IPs to ignore, one per line")
    p.add_argument("--resolver", action="append", metavar="IP",
                   help="(dns) corporate resolver IP; repeatable. Default: any private IP is trusted")
    _add_output(p)
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("phish", help="analyse a suspicious email (.eml)")
    p.add_argument("file", help="path to .eml file")
    _add_output(p)
    p.set_defaults(func=cmd_phish)

    p = sub.add_parser("ioc", help="extract, enrich, defang or refang indicators")
    p.add_argument("action", choices=("extract", "enrich", "defang", "refang"))
    p.add_argument("values", nargs="*", help="indicators, text, or file paths (extract); stdin if empty")
    p.add_argument("--file", help="(enrich) file with one indicator per line")
    p.add_argument("--online", action="store_true",
                   help="(enrich) query VirusTotal / AbuseIPDB using VT_API_KEY / ABUSEIPDB_API_KEY")
    p.add_argument("--include-private", action="store_true", help="(extract) keep private/internal IPs")
    p.add_argument("--raw", action="store_true", help="(extract) print indicators without defanging")
    p.add_argument("--plain", action="store_true", help="(extract) one indicator per line, no headings")
    _add_output(p)
    p.set_defaults(func=cmd_ioc)

    p = sub.add_parser("decode", help="decode Base64 / PowerShell -enc / URL / hex layers")
    p.add_argument("data", nargs="*", help="encoded string or command line; stdin if empty")
    _add_output(p)
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("rules", help="list every detection rule with its MITRE ATT&CK mapping")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("demo", help="run every module against the bundled sample data")
    p.add_argument("--samples", default=str(SAMPLES_DIR), help="sample data directory")
    _add_output(p)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("web", help="start the local browser UI")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1 - local only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    p.set_defaults(func=cmd_web)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if hasattr(args, "min_severity"):
            Severity.parse(args.min_severity)
        return args.func(args)
    except (LogFormatError, ValueError, FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        print(f"soc: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
