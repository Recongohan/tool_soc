"""End-to-end and unit tests. Run with:  python -m pytest   (or)   python -m unittest"""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from soctool.cli import main, run_hunt
from soctool.core.models import Severity
from soctool.core.render import render
from soctool.core.textutil import base_domain, brand_lookalike, dga_score, shannon_entropy
from soctool.ioc.decode import decode_layers
from soctool.ioc.enrich import enrich
from soctool.ioc.extract import classify, defang, extract, refang
from soctool.phish.analyzer import analyze

ROOT = Path(__file__).resolve().parent.parent


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "samples" / "generate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SampleData(unittest.TestCase):
    tmp: Path

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="soctool-test-"))
        gen = _load_generator()
        gen.R.seed(7)
        gen.gen_dns(cls.tmp)
        gen.gen_web(cls.tmp)
        gen.gen_auth(cls.tmp)
        gen.gen_conn(cls.tmp)
        (cls.tmp / "phish.eml").write_text(gen.PHISH)
        (cls.tmp / "benign.eml").write_text(gen.BENIGN)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rules(self, report):
        return {(f.rule_id, f.entity): f for f in report.findings}


class TestHunters(SampleData):
    def test_dns_finds_every_planted_attack_and_nothing_else(self):
        r = run_hunt("dns", str(self.tmp / "dns.csv"))
        got = self.rules(r)
        self.assertIn(("DNS-001", "10.0.1.15 -> exfil-cdn.net"), got)
        self.assertIn(("DNS-003", "10.0.1.23"), got)
        self.assertEqual(got[("DNS-003", "10.0.1.23")].severity, Severity.CRITICAL)  # a DGA domain resolved
        self.assertIn(("DNS-004", "10.0.1.42"), got)
        self.assertIn(("DNS-005", "secure-login-update.com"), got)
        self.assertEqual(len(r.findings), 4, [k for k in got])

    def test_dns_allowlist_and_thresholds(self):
        r = run_hunt("dns", str(self.tmp / "dns.csv"), allow={"exfil-cdn.net"})
        self.assertNotIn("DNS-001", {f.rule_id for f in r.findings})
        r = run_hunt("dns", str(self.tmp / "dns.csv"), settings={"tunnel_min_queries": 10_000})
        self.assertNotIn("DNS-001", {f.rule_id for f in r.findings})

    def test_dns_explicit_resolvers(self):
        r = run_hunt("dns", str(self.tmp / "dns.csv"), resolvers={"10.0.0.99"})
        rogue = [f for f in r.findings if f.rule_id == "DNS-004"]
        self.assertGreater(len(rogue), 1)  # now even 10.0.0.53 is "non-corporate"

    def test_web(self):
        got = self.rules(run_hunt("web", str(self.tmp / "access.log")))
        self.assertEqual(got[("WEB-003", "/uploads/images/logo.php")].severity, Severity.CRITICAL)
        self.assertEqual(got[("WEB-005", "192.0.2.77")].severity, Severity.CRITICAL)
        self.assertIn(("WEB-001", "203.0.113.50"), got)
        self.assertIn(("WEB-004", "198.51.100.7"), got)
        self.assertIn(("WEB-006", "203.0.113.50"), got)
        self.assertEqual(got[("WEB-002", "10.0.5.5")].severity, Severity.LOW)
        legit_users = {e for (_, e) in got} - {"192.0.2.77", "198.51.100.7", "203.0.113.50", "10.0.5.5",
                                               "/uploads/images/logo.php"}
        self.assertEqual(legit_users, set(), "normal visitors must not be flagged")

    def test_auth(self):
        got = self.rules(run_hunt("auth", str(self.tmp / "auth.csv")))
        self.assertEqual(got[("AUTH-001", "jsmith <- 185.220.101.5")].severity, Severity.CRITICAL)
        spray = got[("AUTH-002", "91.240.118.2")]
        self.assertEqual(spray.severity, Severity.CRITICAL)
        self.assertIn("mlee", spray.description)
        self.assertIn(("AUTH-003", "akhan"), got)
        self.assertEqual(len(got), 3)

    def test_beacon(self):
        r = run_hunt("beacon", str(self.tmp / "conn.csv"))
        self.assertEqual([(f.rule_id, f.entity) for f in r.findings], [("NET-001", "10.0.1.15 -> 45.33.32.156:443")])

    def test_zeek_json_lines(self):
        path = self.tmp / "zeek_dns.log"
        lines = []
        for i in range(15):
            sub = base64.b32encode(f"secret-chunk-{i:04d}-0123456789abcdef".encode()).decode().lower().rstrip("=")
            lines.append(json.dumps({"ts": 1763625600 + i, "id.orig_h": "10.9.9.9", "id.resp_h": "10.0.0.53",
                                     "query": f"{sub}.tunnel.example", "qtype_name": "TXT", "rcode_name": "NOERROR"}))
        path.write_text("\n".join(lines))
        r = run_hunt("dns", str(path))
        self.assertEqual([f.rule_id for f in r.findings], ["DNS-001"])

    def test_missing_columns_is_a_clear_error(self):
        path = self.tmp / "bad.csv"
        path.write_text("a,b\n1,2\n")
        rc = main(["hunt", "dns", str(path)])
        self.assertEqual(rc, 1)


class TestPhish(SampleData):
    def test_phish_sample(self):
        r = analyze(str(self.tmp / "phish.eml"))
        ids = {f.rule_id for f in r.findings}
        self.assertTrue({"PHISH-001", "PHISH-002", "PHISH-003", "PHISH-004", "PHISH-005", "PHISH-006"} <= ids)
        verdict = dict(r.sections[0].rows)
        self.assertEqual(verdict["Verdict"], "LIKELY PHISHING")
        block = next(s for s in r.sections if s.heading.startswith("Block list"))
        self.assertNotIn("bit[.]ly", dict(block.rows)["Domains"])  # never block shared infra

    def test_benign_sample(self):
        r = analyze(str(self.tmp / "benign.eml"))
        self.assertEqual(r.findings, [])
        self.assertEqual(dict(r.sections[0].rows)["Verdict"], "NO STRONG INDICATORS")


class TestIOC(unittest.TestCase):
    def test_refang_defang_roundtrip(self):
        self.assertEqual(refang("hxxps://evil[.]example[.]com/a"), "https://evil.example.com/a")
        self.assertEqual(defang("https://evil.example.com/a.php"), "hxxps[://]evil[.]example[.]com/a.php")
        self.assertEqual(refang(defang("https://a.b.co.uk/x?y=1")), "https://a.b.co.uk/x?y=1")
        self.assertEqual(defang("1.2.3.4"), "1[.]2[.]3[.]4")

    def test_extract(self):
        text = ("C2 at hxxp://185.193.88[.]4/gate.php and cdn-update[.]top, dropped payload.exe, "
                "sha256 " + "ab" * 32 + ", CVE-2024-3400, 10.0.0.5, (New-Object Net.WebClient)")
        iocs = extract(text)
        self.assertEqual(iocs.ipv4, ["185.193.88.4"])
        self.assertIn("cdn-update.top", iocs.domains)
        self.assertNotIn("payload.exe", iocs.domains)
        self.assertNotIn("net.webclient", iocs.domains)
        self.assertEqual(iocs.cves, ["CVE-2024-3400"])
        self.assertEqual(len(iocs.sha256), 1)
        self.assertIn("10.0.0.5", extract(text, include_private=True).ipv4)

    def test_classify(self):
        cases = {"8.8.8.8": "ip", "evil.com": "domain", "hxxp://a[.]b/c": "url", "x@y.com": "email",
                 "d41d8cd98f00b204e9800998ecf8427e": "md5", "CVE-2021-44228": "cve", "hello": "unknown"}
        for value, kind in cases.items():
            self.assertEqual(classify(value), kind, value)

    def test_enrich_offline(self):
        r = enrich(["paypa1-secure[.]com", "google.com", "10.1.1.1"])
        flagged = {f.entity for f in r.findings}
        self.assertEqual(flagged, {"paypa1-secure[.]com"})

    def test_enrich_online_with_fake_fetcher(self):
        import os
        calls = []

        def fake(url, headers):
            calls.append(url)
            if "virustotal" in url:
                return {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1}}}}
            return {"data": {"abuseConfidenceScore": 100, "totalReports": 50, "countryCode": "NL", "isp": "x"}}

        old = {k: os.environ.get(k) for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY")}
        os.environ["VT_API_KEY"] = os.environ["ABUSEIPDB_API_KEY"] = "dummy"
        try:
            r = enrich(["45.33.32.156", "192.168.1.1"], online=True, fetch=fake)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertTrue(all("192.168.1.1" not in c for c in calls), "private IPs must never be sent out")
        sevs = sorted(f.severity for f in r.findings if f.rule_id == "IOC-002")
        self.assertEqual(sevs, [Severity.HIGH, Severity.CRITICAL])


class TestHeuristics(unittest.TestCase):
    def test_dga_score_separates_words_from_noise(self):
        for good in ("google.com", "microsoft.com", "wikipedia.org", "github.com", "atlassian.net"):
            self.assertLess(dga_score(good), 0.5, good)
        for bad in ("qx7kzv9pwr2m.top", "xkcdqwpzlv.xyz", "a8x9k2m4q.biz"):
            self.assertGreaterEqual(dga_score(bad), 0.5, bad)

    def test_brand_lookalike(self):
        self.assertIsNotNone(brand_lookalike("paypa1.com"))
        self.assertIsNotNone(brand_lookalike("login-microsoft-support.com"))
        self.assertIsNotNone(brand_lookalike("rnicrosoft.com"))
        self.assertIsNone(brand_lookalike("paypal.com"))
        self.assertIsNone(brand_lookalike("purchase-orders.com"))  # contains "chase" but isn't
        self.assertIsNone(brand_lookalike("pineapple.com"))

    def test_base_domain_and_entropy(self):
        self.assertEqual(base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(base_domain("x.y.evil.com"), "evil.com")
        self.assertGreater(shannon_entropy("aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh"), shannon_entropy("aaaabbbb"))

    def test_decode_powershell_and_nested(self):
        ps = base64.b64encode("Write-Host pwned".encode("utf-16-le")).decode()
        layers = decode_layers(f"powershell -NoP -enc {ps}")
        self.assertEqual(layers[-1][1], "Write-Host pwned")
        nested = base64.b64encode(b"hello%20world%21").decode()
        self.assertEqual(decode_layers(nested)[-1][1], "hello world!")


class TestCliAndRender(SampleData):
    def test_all_formats_render(self):
        r = run_hunt("auth", str(self.tmp / "auth.csv"))
        for fmt in ("text", "json", "csv", "markdown"):
            buf = io.StringIO()
            render(r, fmt, buf)
            self.assertIn("AUTH-002", buf.getvalue(), fmt)
        data = json.loads(_render(r, "json"))
        self.assertEqual(data["findings"][0]["severity"], "CRITICAL")

    def test_fail_on_exit_code(self):
        self.assertEqual(main(["hunt", "beacon", str(self.tmp / "conn.csv"), "--fail-on", "high", "-f", "json",
                               "-o", str(self.tmp / "out.json")]), 2)
        self.assertEqual(main(["hunt", "beacon", str(self.tmp / "conn.csv"), "--fail-on", "critical", "-f", "json",
                               "-o", str(self.tmp / "out.json")]), 0)


def _render(report, fmt):
    buf = io.StringIO()
    render(report, fmt, buf)
    return buf.getvalue()


class TestWebServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from soctool.web.server import make_server
        cls.httpd = make_server("127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def post(self, path, body, ctype="application/json", host=None):
        headers = {"Content-Type": ctype}
        if host:
            headers["Host"] = host
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_index_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/") as resp:
            self.assertIn("default-src 'self'", resp.headers["Content-Security-Policy"])
            self.assertIn(b"SOC Toolkit", resp.read())

    def test_decode_api(self):
        ps = base64.b64encode("IEX evil".encode("utf-16-le")).decode()
        status, data = self.post("/api/decode", {"text": f"powershell -enc {ps}"})
        self.assertEqual(status, 200)
        self.assertEqual(data["report"]["findings"][0]["rule_id"], "DEC-001")
        self.assertIn("markdown", data)

    def test_hunt_api_with_pasted_lines(self):
        lines = "timestamp,user,src_ip,result\n" + "".join(
            f"2026-11-20T10:00:{i:02d}Z,user{i},203.0.113.9,failure\n" for i in range(12))
        status, data = self.post("/api/hunt", {"kind": "auth", "content": lines})
        self.assertEqual(status, 200)
        self.assertEqual(data["report"]["findings"][0]["rule_id"], "AUTH-002")

    def test_rejects_non_json_and_foreign_host(self):
        self.assertEqual(self.post("/api/decode", {"text": "x"}, ctype="text/plain")[0], 415)
        self.assertEqual(self.post("/api/decode", {"text": "x"}, host="attacker.example")[0], 403)

    def test_path_traversal_blocked(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + "/../server.py")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
