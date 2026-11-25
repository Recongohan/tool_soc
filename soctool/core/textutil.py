"""String heuristics used across hunters: entropy, domain parsing, DGA scoring, lookalikes."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter

# Small list of multi-label public suffixes so that base_domain("a.b.co.uk") == "b.co.uk".
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "gov.in",
    "co.nz", "org.nz", "com.br", "net.br", "com.cn", "net.cn", "org.cn",
    "com.mx", "co.za", "com.sg", "com.tr", "com.pk", "com.bd", "co.kr",
}

# Cheap / free TLDs that are over-represented in abuse feeds (Spamhaus, Interisle reports).
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "zip", "mov",
    "rest", "country", "kim", "loan", "men", "party", "racing", "review", "stream",
    "download", "cam", "icu", "buzz", "monster", "cyou", "sbs", "cfd", "quest", "bond",
    "lol", "ru.com", "su", "pw", "cc", "ws",
}

VOWELS = set("aeiouy")

# brand keyword -> registrable domains that legitimately belong to it
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com", "office365.com"),
    "office365": ("microsoft.com", "office.com", "office365.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "microsoft.com", "live.com"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com"),
    "google": ("google.com", "gmail.com", "googleapis.com", "youtube.com"),
    "netflix": ("netflix.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com",),
    "linkedin": ("linkedin.com",),
    "adobe": ("adobe.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})


def shannon_entropy(text: str) -> float:
    """Bits per character. English words sit ~2.5-3.2; Base64 blobs ~4.5-6."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def normalise_domain(name: str) -> str:
    return name.strip().strip(".").lower()


def base_domain(name: str) -> str:
    """Registrable domain (eTLD+1) using a small built-in suffix list."""
    name = normalise_domain(name)
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_part(name: str) -> str:
    """Everything left of the registrable domain ("" if none)."""
    name = normalise_domain(name)
    base = base_domain(name)
    if name == base:
        return ""
    return name[: -len(base) - 1]


def tld(name: str) -> str:
    return normalise_domain(name).rsplit(".", 1)[-1]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip().strip("[]")).is_global
    except ValueError:
        return False


def _longest_consonant_run(label: str) -> int:
    best = run = 0
    for ch in label:
        if ch.isalnum() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def dga_score(domain: str) -> float:
    """0..1 score of how 'machine-generated' the registrable label looks.

    Cheap lexical features only (vowel ratio, consonant runs, letter/digit mix,
    entropy, TLD reputation) so it runs offline on millions of rows. It is a
    triage signal, not a verdict - real DGA detection pairs this with
    NXDOMAIN volume, which is how the DNS hunter uses it.
    """
    domain = normalise_domain(domain)
    if not domain or is_ip(domain):
        return 0.0
    label = base_domain(domain).split(".")[0].replace("-", "")
    if len(label) < 6:
        return 0.0
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    score = 0.0

    vowel_ratio = (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0
    if vowel_ratio < 0.2:
        score += 0.3
    elif vowel_ratio < 0.3:
        score += 0.15

    run = _longest_consonant_run(label)
    if run >= 5:
        score += 0.25
    elif run >= 4:
        score += 0.15

    if letters and digits and digits / len(label) > 0.2:
        score += 0.25
    if shannon_entropy(label) >= 3.3:
        score += 0.2
    if tld(domain) in SUSPICIOUS_TLDS:
        score += 0.15
    if len(label) >= 15:
        score += 0.1
    return round(min(score, 1.0), 2)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_lookalike(domain: str) -> tuple[str, str] | None:
    """Detect brand abuse. Returns (brand, reason) or None.

    Catches: brand keyword in a non-brand domain (paypal-secure-login.com),
    homoglyph / typo squats (paypa1.com, rnicrosoft.com, amazom.com).
    """
    domain = normalise_domain(domain)
    if not domain or is_ip(domain):
        return None
    base = base_domain(domain)
    for brand, legit in BRANDS.items():
        if base in legit:
            return None
    label = base.split(".")[0]
    tokens = set(re.split(r"[-._\d]+", domain))
    unglyphed = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand, legit in BRANDS.items():
        if brand in tokens or (len(brand) >= 5 and label.startswith(brand)):
            return brand, f"contains brand name '{brand}' but is not a {brand} domain"
        if unglyphed != label and brand in unglyphed:
            return brand, f"homoglyph of '{brand}' ({label} -> {unglyphed})"
        for legit_domain in legit:
            legit_label = legit_domain.split(".")[0]
            if len(legit_label) >= 5 and label != legit_label and levenshtein(unglyphed, legit_label) == 1:
                return brand, f"typosquat of {legit_domain} (edit distance 1)"
    return None
