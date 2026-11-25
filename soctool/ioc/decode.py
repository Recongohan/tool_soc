"""Peel back common obfuscation layers: Base64, PowerShell -EncodedCommand, URL and hex encoding."""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

from soctool.core.models import Report, Section, Severity
from soctool.core.rules import finding
from soctool.ioc.extract import defang, extract

PS_ENC = re.compile(r"-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|"
                    r"encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", re.I)
B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")

SUSPICIOUS = re.compile(
    r"invoke-expression|\biex\b|downloadstring|downloadfile|net\.webclient|invoke-webrequest|"
    r"frombase64string|start-process|-nop\b|-w(indowstyle)?\s+hidden|bypass|mimikatz|"
    r"new-object|reflection\.assembly|virtualalloc|/bin/(ba)?sh|wget |curl |certutil|bitsadmin|"
    r"regsvr32|rundll32|mshta|powershell", re.I)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text)


def _try_b64(token: str) -> tuple[str, str] | None:
    padded = token + "=" * (-len(token) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        # PowerShell -EncodedCommand is UTF-16LE: every other byte is NUL.
        if len(raw) >= 4 and raw[1::2].count(0) >= len(raw[1::2]) * 0.8:
            try:
                text = raw.decode("utf-16-le")
                if _printable_ratio(text) > 0.9:
                    return "base64 (UTF-16LE / PowerShell)", text
            except UnicodeDecodeError:
                pass
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(text) > 0.9 and len(text.strip()) >= 4:
            return "base64", text
    return None


def decode_layers(data: str, max_depth: int = 5) -> list[tuple[str, str]]:
    """Return [(encoding, decoded_text), ...] applying decoders repeatedly."""
    layers: list[tuple[str, str]] = []
    current = data.strip()
    for _ in range(max_depth):
        step = None
        m = PS_ENC.search(current)
        if m:
            res = _try_b64(m.group(2))
            if res:
                step = ("PowerShell -EncodedCommand", res[1])
        if step is None and re.search(r"%[0-9a-fA-F]{2}", current):
            decoded = unquote(current)
            if decoded != current:
                step = ("URL encoding", decoded)
        if step is None:
            stripped = current.strip().strip("'\"")
            if re.fullmatch(r"[A-Za-z0-9+/_-]{8,}={0,2}", stripped):
                res = _try_b64(stripped)
                if res:
                    step = res
        if step is None:
            hm = re.fullmatch(r"(?:0x)?((?:[0-9a-fA-F]{2}){4,})", current.strip())
            if hm:
                try:
                    text = bytes.fromhex(hm.group(1)).decode("utf-8")
                    if _printable_ratio(text) > 0.9:
                        step = ("hex", text)
                except (ValueError, UnicodeDecodeError):
                    pass
        if step is None:
            # embedded base64 blob inside a longer command line, e.g. FromBase64String('...')
            for tok in sorted(B64_TOKEN.findall(current), key=len, reverse=True):
                if len(tok) < 20:
                    break
                res = _try_b64(tok)
                if res:
                    step = (res[0] + " (embedded)", current.replace(tok, res[1]) if len(tok) < len(current) else res[1])
                    break
        if step is None or step[1] == current:
            break
        layers.append(step)
        current = step[1]
    return layers


def decode_report(data: str) -> Report:
    report = Report(title="Decode")
    layers = decode_layers(data)
    s = Section("Input")
    s.add("Length", len(data))
    s.add("Layers decoded", len(layers))
    report.sections.append(s)
    for i, (enc, text) in enumerate(layers, 1):
        sec = Section(f"Layer {i}: {enc}")
        sec.add("Output", text if len(text) <= 2000 else text[:2000] + " ...[truncated]")
        report.sections.append(sec)
    final = layers[-1][1] if layers else data
    iocs = extract(final)
    if iocs.total():
        sec = Section("IOCs in decoded output (defanged)")
        for kind, vals in iocs.items():
            if vals:
                sec.add(kind, [defang(v) for v in vals])
        report.sections.append(sec)
    if layers:
        hits = sorted({m.group(0).strip().lower() for m in SUSPICIOUS.finditer(final)})
        sev = Severity.HIGH if hits else Severity.LOW
        desc = f"{len(layers)} encoding layer(s): {' -> '.join(e for e, _ in layers)}."
        if hits:
            desc += f" Decoded content uses: {', '.join(hits)}."
        report.findings.append(finding("DEC-001", sev, "input", desc, [final[:300]]))
    return report
