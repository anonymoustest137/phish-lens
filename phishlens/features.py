"""Explainable phishing features for URLs and email text."""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work"}
URGENCY = ["urgent", "immediately", "verify your account", "suspended", "act now",
           "within 24 hours", "final notice", "confirm your identity", "unusual activity"]
CREDS = ["password", "login", "sign in", "credentials", "ssn", "credit card", "bank account"]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
BRANDS = ["paypal", "microsoft", "apple", "amazon", "netflix", "google", "dhl", "fedex"]


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def url_features(url):
    """Return (features dict, list of human-readable reasons)."""
    p = urlparse(url if "://" in url else "http://" + url)
    host = (p.hostname or "").lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    reasons = []
    f = {}

    f["url_length"] = len(url)
    if len(url) > 75:
        reasons.append("Unusually long URL (" + str(len(url)) + " chars)")

    f["has_ip"] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    if f["has_ip"]:
        reasons.append("Uses a raw IP address instead of a domain")

    f["subdomain_count"] = max(0, host.count(".") - 1)
    if f["subdomain_count"] >= 3:
        reasons.append("Deeply nested subdomains (" + str(f["subdomain_count"]) + ")")

    f["has_at"] = 1 if "@" in url else 0
    if f["has_at"]:
        reasons.append("Contains '@' which can hide the true destination")

    f["hyphens"] = host.count("-")
    if f["hyphens"] >= 2:
        reasons.append("Multiple hyphens in hostname")

    f["suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0
    if f["suspicious_tld"]:
        reasons.append("High-risk TLD: ." + tld)

    f["is_shortener"] = 1 if host in SHORTENERS else 0
    if f["is_shortener"]:
        reasons.append("URL shortener hides the real target")

    f["entropy"] = round(shannon_entropy(host), 3)
    if f["entropy"] > 4.0:
        reasons.append("High-entropy hostname (possible DGA)")

    f["https"] = 1 if p.scheme == "https" else 0
    if not f["https"]:
        reasons.append("No HTTPS")

    f["brand_in_subdomain"] = 0
    for b in BRANDS:
        if b in host and not host.endswith(b + ".com"):
            f["brand_in_subdomain"] = 1
            reasons.append("Impersonates brand '" + b + "' outside its real domain")
            break

    return f, reasons


def text_features(text):
    """Return (features dict, reasons) for an email body."""
    t = (text or "").lower()
    reasons = []
    f = {}

    hits = [w for w in URGENCY if w in t]
    f["urgency_hits"] = len(hits)
    if hits:
        reasons.append("Urgency language: " + ", ".join(hits[:3]))

    creds = [w for w in CREDS if w in t]
    f["credential_hits"] = len(creds)
    if creds:
        reasons.append("Requests credentials: " + ", ".join(creds[:3]))

    f["link_count"] = len(re.findall(r"https?://", t))
    f["exclamations"] = t.count("!")
    if f["exclamations"] >= 3:
        reasons.append("Excessive exclamation marks")

    caps = re.findall(r"\b[A-Z]{4,}\b", text or "")
    f["shouting"] = len(caps)
    if caps:
        reasons.append("ALL-CAPS words: " + ", ".join(caps[:3]))

    f["generic_greeting"] = 1 if re.search(r"dear (customer|user|sir|madam)", t) else 0
    if f["generic_greeting"]:
        reasons.append("Generic greeting instead of your name")

    return f, reasons
