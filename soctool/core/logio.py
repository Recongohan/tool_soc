"""Reading log files (CSV or JSON Lines) and parsing timestamps.

Hunters describe the columns they need; aliases let the same hunter read
our simple CSV layout *and* Zeek / common SIEM export field names.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterator

csv.field_size_limit(10 * 1024 * 1024)


class LogFormatError(ValueError):
    pass


def open_text(path: str) -> io.TextIOBase:
    if path == "-":
        return sys.stdin
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def read_records(path: str, aliases: dict[str, str] | None = None,
                 required: tuple[str, ...] = ()) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield (line_number, record) from a CSV-with-header or JSON Lines file.

    Field names are lower-cased and mapped through ``aliases`` so that e.g.
    Zeek's ``id.orig_h`` becomes ``src_ip``.
    """
    aliases = {k.lower(): v for k, v in (aliases or {}).items()}

    def normalise(raw: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in raw.items():
            if key is None:
                continue
            k = key.strip().lower()
            out[aliases.get(k, k)] = value
        return out

    fh = open_text(path)
    try:
        first = ""
        while True:
            pos_line = fh.readline()
            if not pos_line:
                return
            if pos_line.strip() and not pos_line.lstrip().startswith("#"):
                first = pos_line
                break

        if first.lstrip().startswith("{"):
            lines = _chain([first], fh)
            for n, line in enumerate(lines, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rec = normalise(json.loads(line))
                except json.JSONDecodeError:
                    continue
                yield n, rec
        else:
            reader = csv.DictReader(_chain([first], fh))
            header = [aliases.get(h.strip().lower(), h.strip().lower()) for h in (reader.fieldnames or [])]
            missing = [c for c in required if c not in header]
            if missing:
                raise LogFormatError(
                    f"{path}: missing required column(s) {', '.join(missing)}; found {', '.join(header)}"
                )
            for n, row in enumerate(reader, start=2):
                yield n, normalise(row)
    finally:
        if fh is not sys.stdin:
            fh.close()


def _chain(head: list[str], rest: Iterator[str]) -> Iterator[str]:
    yield from head
    yield from rest


_TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",  # Apache / Nginx
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%b %d %Y %H:%M:%S",
)


def parse_time(value: Any) -> datetime | None:
    """Parse epoch seconds, ISO-8601 or web-server timestamps into aware UTC datetimes."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except ValueError:
        pass
    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        dt = None
        for fmt in _TIME_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_time(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def as_list(value: Any) -> list[str]:
    """Answers/TTLs may arrive as JSON lists or ';' / ',' / '|' separated strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text or text == "-":
        return []
    for sep in (";", "|", ","):
        if sep in text:
            return [p.strip() for p in text.split(sep) if p.strip()]
    return [text]


def max_in_window(times: list[datetime], window_seconds: float) -> tuple[int, int, int]:
    """Largest number of events inside any sliding window.

    ``times`` must be sorted. Returns (count, start_index, end_index_inclusive).
    """
    best = (0, 0, -1)
    left = 0
    for right, t in enumerate(times):
        while (t - times[left]).total_seconds() > window_seconds:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, left, right)
    return best
