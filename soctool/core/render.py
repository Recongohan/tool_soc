"""Render a Report as coloured terminal text, JSON, CSV or ticket-ready Markdown."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from typing import Any, TextIO

from soctool.core.models import Report, Severity
from soctool.core.rules import technique_name

FORMATS = ("text", "json", "csv", "markdown")

_COLOURS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[2m",
}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"


def _use_colour(stream: TextIO, forced: bool | None) -> bool:
    if forced is not None:
        return forced
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _fmt_value(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value) if value else "-"
    if value is None or value == "":
        return "-"
    return str(value)


def render(report: Report, fmt: str = "text", stream: TextIO | None = None,
           min_severity: Severity = Severity.INFO, colour: bool | None = None,
           max_evidence: int = 8) -> None:
    stream = stream or sys.stdout
    if fmt == "json":
        json.dump(report.to_dict(min_severity), stream, indent=2, default=str)
        stream.write("\n")
    elif fmt == "csv":
        _render_csv(report, stream, min_severity)
    elif fmt == "markdown":
        stream.write(render_markdown(report, min_severity, max_evidence))
    else:
        _render_text(report, stream, min_severity, _use_colour(stream, colour), max_evidence)


def _render_text(report: Report, out: TextIO, min_sev: Severity, colour: bool, max_ev: int) -> None:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    out.write(c(_BOLD, f"== {report.title} ==") + "\n")
    for section in report.sections:
        if not section.rows:
            continue
        out.write("\n" + c(_BOLD, section.heading) + "\n")
        width = max(len(k) for k, _ in section.rows)
        for key, value in section.rows:
            out.write(f"  {key.ljust(width)} : {_fmt_value(value)}\n")

    findings = report.sorted_findings(min_sev)
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    summary = "  ".join(
        c(_COLOURS[s], f"{s.name}:{counts[s]}") for s in sorted(Severity, reverse=True) if counts[s]
    )
    out.write("\n" + c(_BOLD, f"Findings ({len(findings)})") + ("  " + summary if summary else "") + "\n")
    if not findings:
        out.write("  No findings at or above the selected severity.\n")
        return

    for f in findings:
        tag = c(_COLOURS[f.severity], f"[{f.severity.name}]")
        out.write(f"\n{tag} {c(_BOLD, f.rule_id)}  {f.title}\n")
        out.write(f"  entity   : {f.entity}\n")
        if f.first_seen or f.last_seen:
            out.write(f"  window   : {f.first_seen or '?'} -> {f.last_seen or '?'}\n")
        if f.mitre:
            out.write("  mitre    : " + "; ".join(f"{t} {technique_name(t)}".strip() for t in f.mitre) + "\n")
        out.write(f"  detail   : {f.description}\n")
        if f.evidence:
            out.write("  evidence :\n")
            for line in f.evidence[:max_ev]:
                out.write(c(_DIM, f"    - {line}") + "\n")
            if len(f.evidence) > max_ev:
                out.write(c(_DIM, f"    ... {len(f.evidence) - max_ev} more (use --format json for all)") + "\n")


def _render_csv(report: Report, out: TextIO, min_sev: Severity) -> None:
    writer = csv.writer(out)
    writer.writerow(["severity", "rule_id", "title", "entity", "description", "mitre",
                     "first_seen", "last_seen", "evidence"])
    for f in report.sorted_findings(min_sev):
        writer.writerow([f.severity.name, f.rule_id, f.title, f.entity, f.description,
                         " ".join(f.mitre), f.first_seen or "", f.last_seen or "",
                         " | ".join(f.evidence)])


def render_markdown(report: Report, min_sev: Severity = Severity.INFO, max_ev: int = 8) -> str:
    """Markdown suitable for pasting into a ticket (Jira, ServiceNow, TheHive)."""
    buf = io.StringIO()
    buf.write(f"# {report.title}\n\n")
    for section in report.sections:
        if not section.rows:
            continue
        buf.write(f"## {section.heading}\n\n| Field | Value |\n|---|---|\n")
        for key, value in section.rows:
            buf.write(f"| {key} | {_md_escape(_fmt_value(value))} |\n")
        buf.write("\n")
    findings = report.sorted_findings(min_sev)
    buf.write(f"## Findings ({len(findings)})\n\n")
    if findings:
        buf.write("| Severity | Rule | Entity | Title |\n|---|---|---|---|\n")
        for f in findings:
            buf.write(f"| {f.severity.name} | {f.rule_id} | `{_md_escape(f.entity)}` | {f.title} |\n")
        buf.write("\n")
    for f in findings:
        buf.write(f"### [{f.severity.name}] {f.rule_id} - {f.title}\n\n")
        buf.write(f"- **Entity:** `{f.entity}`\n")
        if f.first_seen or f.last_seen:
            buf.write(f"- **Window:** {f.first_seen or '?'} -> {f.last_seen or '?'}\n")
        if f.mitre:
            buf.write("- **MITRE ATT&CK:** " + ", ".join(f"{t} ({technique_name(t)})" for t in f.mitre) + "\n")
        buf.write(f"- **Detail:** {f.description}\n")
        if f.evidence:
            buf.write("\n```\n" + "\n".join(f.evidence[:max_ev]) + "\n```\n")
        buf.write("\n")
    return buf.getvalue()


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
