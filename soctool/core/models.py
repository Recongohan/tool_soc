"""Data model shared by every module: findings, report sections and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {names})") from exc


@dataclass
class Finding:
    """One detection: what fired, how bad it is, who it is about and why."""

    rule_id: str
    title: str
    severity: Severity
    entity: str
    description: str
    mitre: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        from soctool.core.rules import technique_name

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "entity": self.entity,
            "description": self.description,
            "mitre": [{"id": t, "name": technique_name(t)} for t in self.mitre],
            "evidence": self.evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Section:
    """A block of key/value facts shown above the findings (summary, headers, ...)."""

    heading: str
    rows: list[tuple[str, Any]] = field(default_factory=list)

    def add(self, key: str, value: Any) -> None:
        self.rows.append((key, value))


@dataclass
class Report:
    title: str
    sections: list[Section] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self, min_severity: Severity = Severity.INFO) -> list[Finding]:
        kept = [f for f in self.findings if f.severity >= min_severity]
        return sorted(kept, key=lambda f: (-f.severity, f.rule_id, f.entity))

    def to_dict(self, min_severity: Severity = Severity.INFO) -> dict[str, Any]:
        return {
            "title": self.title,
            "sections": [
                {"heading": s.heading, "data": {k: v for k, v in s.rows}} for s in self.sections
            ],
            "findings": [f.to_dict() for f in self.sorted_findings(min_severity)],
        }
