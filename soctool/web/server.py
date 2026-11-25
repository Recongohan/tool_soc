"""Local web UI: a small JSON API over the same engine the CLI uses.

Started with ``soc web``. Binds to 127.0.0.1 by default and uses only the
standard library. Hardening for a tool that handles hostile input:

* Host header allow-list (defeats DNS-rebinding attacks against localhost).
* POST endpoints accept ``application/json`` only, so a malicious web page
  cannot submit a cross-site form to them without a CORS preflight.
* Strict Content-Security-Policy; the front end renders every string from a
  report with ``textContent``, never as HTML.
* Uploads are size-capped and written to a private temp dir that is deleted
  after each analysis.
"""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from soctool import __version__
from soctool.core.logio import LogFormatError
from soctool.core.models import Report
from soctool.core.render import render_markdown
from soctool.core.rules import RULES, technique_name

STATIC = Path(__file__).resolve().parent / "static"
SAMPLES = Path(__file__).resolve().parent.parent.parent / "samples"
MAX_BODY = 60 * 1024 * 1024
SAMPLE_FILES = {"dns": "dns.csv", "web": "access.log", "auth": "auth.csv", "beacon": "conn.csv",
                "phish": "phish.eml", "benign": "benign.eml", "iocs": "iocs.txt"}

HUNTER_INFO = {
    "dns": {"label": "DNS", "accepts": ".csv,.json,.jsonl,.log,.txt",
            "hint": "CSV/JSONL with src_ip, query - plus qtype, rcode, resolver, answers, ttl. Zeek dns.log JSON works."},
    "web": {"label": "Web server", "accepts": ".log,.txt,.access",
            "hint": "Apache / Nginx combined log format (access.log)."},
    "auth": {"label": "Authentication", "accepts": ".csv,.json,.jsonl,.txt",
             "hint": "CSV/JSONL with timestamp, user, src_ip, result - plus optional country, service."},
    "beacon": {"label": "Connections", "accepts": ".csv,.json,.jsonl,.log,.txt",
               "hint": "CSV/JSONL with timestamp, src_ip, dst - plus dst_port, bytes_out. Zeek conn.log JSON works."},
}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _payload(report: Report) -> dict[str, Any]:
    from soctool.core.render import render
    import io

    buf = io.StringIO()
    render(report, "csv", buf)
    return {"report": report.to_dict(), "markdown": render_markdown(report, max_ev=20), "csv": buf.getvalue()}


def _with_temp(content: bytes, suffix: str, fn):
    with tempfile.TemporaryDirectory(prefix="soctool-") as tmp:
        path = os.path.join(tmp, "upload" + suffix)
        with open(path, "wb") as fh:
            fh.write(content)
        return fn(path)


def _decode_upload(body: dict[str, Any]) -> bytes:
    if "content_b64" in body:
        try:
            return base64.b64decode(body["content_b64"], validate=True)
        except ValueError as exc:
            raise ApiError("upload is not valid base64") from exc
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ApiError("no content supplied - choose a file, paste text or load a sample")
    return content.encode("utf-8")


def _settings(raw: Any) -> dict[str, float]:
    out: dict[str, float] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        if value in (None, ""):
            continue
        try:
            out[str(key)] = float(value)
        except (TypeError, ValueError) as exc:
            raise ApiError(f"threshold {key} must be a number") from exc
    return out


def api_meta(_: dict[str, Any]) -> dict[str, Any]:
    from soctool.cli import hunter_defaults
    return {
        "version": __version__,
        "hunters": {k: {**v, "defaults": hunter_defaults(k)} for k, v in HUNTER_INFO.items()},
        "rules": [{"id": r.rule_id, "title": r.title, "description": r.description,
                   "mitre": [{"id": t, "name": technique_name(t)} for t in r.mitre]} for r in RULES.values()],
        "samples": {k: (SAMPLES / v).exists() for k, v in SAMPLE_FILES.items()},
        "online_keys": {"virustotal": bool(os.environ.get("VT_API_KEY")),
                        "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY"))},
    }


def api_sample(body: dict[str, Any]) -> dict[str, Any]:
    name = SAMPLE_FILES.get(str(body.get("name")))
    if not name or not (SAMPLES / name).exists():
        raise ApiError("sample not found - run: python samples/generate.py", 404)
    text = (SAMPLES / name).read_text(encoding="utf-8", errors="replace")
    return {"name": name, "content": text, "size": len(text.encode())}


def api_hunt(body: dict[str, Any]) -> dict[str, Any]:
    from soctool.cli import run_hunt
    kind = body.get("kind")
    if kind not in HUNTER_INFO:
        raise ApiError("unknown log type")
    content = _decode_upload(body)
    settings = _settings(body.get("settings"))
    allow = {s.strip().lower() for s in str(body.get("allowlist") or "").splitlines() if s.strip()}
    resolvers = {s.strip() for s in str(body.get("resolvers") or "").replace(",", "\n").splitlines() if s.strip()}
    report = _with_temp(content, ".log", lambda p: run_hunt(kind, p, settings, allow, resolvers))
    report.title = f"{HUNTER_INFO[kind]['label']} hunt - {body.get('filename') or 'pasted log'}"
    return _payload(report)


def api_phish(body: dict[str, Any]) -> dict[str, Any]:
    from soctool.phish.analyzer import analyze
    content = _decode_upload(body)
    report = _with_temp(content, ".eml", analyze)
    report.title = f"Phishing analysis - {body.get('filename') or 'pasted email'}"
    return _payload(report)


def api_enrich(body: dict[str, Any]) -> dict[str, Any]:
    from soctool.ioc.enrich import enrich
    values = [v.strip() for v in str(body.get("values") or "").splitlines()
              if v.strip() and not v.strip().startswith("#")]
    if not values:
        raise ApiError("enter at least one indicator")
    if len(values) > 500:
        raise ApiError("at most 500 indicators per run")
    return _payload(enrich(values, online=bool(body.get("online"))))


def api_extract(body: dict[str, Any]) -> dict[str, Any]:
    from soctool.ioc.extract import defang, extract
    text = str(body.get("text") or "")
    if not text.strip():
        raise ApiError("paste some text to extract indicators from")
    iocs = extract(text, include_private=bool(body.get("include_private")))
    return {"iocs": {k: [{"value": v, "defanged": defang(v)} for v in vals] for k, vals in iocs.items()},
            "total": iocs.total()}


def api_decode(body: dict[str, Any]) -> dict[str, Any]:
    from soctool.ioc.decode import decode_report
    text = str(body.get("text") or "")
    if not text.strip():
        raise ApiError("paste an encoded string or command line")
    return _payload(decode_report(text))


ROUTES = {
    "/api/meta": api_meta, "/api/sample": api_sample, "/api/hunt": api_hunt, "/api/phish": api_phish,
    "/api/ioc/enrich": api_enrich, "/api/ioc/extract": api_extract, "/api/decode": api_decode,
}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = f"soctool/{__version__}"
    allowed_hosts: set[str] = set()

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        if os.environ.get("SOCTOOL_WEB_DEBUG"):
            super().log_message(fmt, *args)

    def _headers(self, status: int, ctype: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _json(self, status: int, data: Any) -> None:
        raw = json.dumps(data, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(raw))
        self.wfile.write(raw)

    def _host_ok(self) -> bool:
        if not self.allowed_hosts:  # bound to all interfaces on purpose
            return True
        host = (self.headers.get("Host") or "").lower()
        if host.startswith("["):  # [::1]:8765
            host = host.split("]")[0] + "]"
        else:
            host = host.rsplit(":", 1)[0]
        return host in self.allowed_hosts

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/meta":
            self._json(HTTPStatus.OK, api_meta({}))
            return
        if path == "/":
            path = "/index.html"
        target = (STATIC / path.lstrip("/")).resolve()
        if STATIC not in target.parents or not target.is_file():
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._headers(HTTPStatus.OK, ctype, len(data))
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
            return
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON body required"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                       {"error": f"file too large (max {MAX_BODY // 1024 // 1024} MB in the browser - use the CLI)"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ApiError("JSON object expected")
            self._json(HTTPStatus.OK, route(body))
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})
        except (LogFormatError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - last-resort guard, keep the server up
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"analysis failed: {exc.__class__.__name__}: {exc}"})


def make_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    wildcard = host in ("0.0.0.0", "::", "")
    Handler.allowed_hosts = set() if wildcard else {"127.0.0.1", "localhost", "[::1]", host.lower()}
    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    httpd = make_server(host, port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{httpd.server_address[1]}/"
    print(f"soctool web UI running at {url}  (Ctrl+C to stop)")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: bound to a non-loopback address; anyone who can reach it can submit data.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
