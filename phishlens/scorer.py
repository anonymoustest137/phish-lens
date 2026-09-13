"""Weighted scoring engine combining URL and text signals."""
from .features import url_features, text_features

WEIGHTS = {
    "has_ip": 25,
    "has_at": 20,
    "suspicious_tld": 18,
    "brand_in_subdomain": 22,
    "is_shortener": 12,
    "subdomain_count": 5,
    "hyphens": 4,
    "urgency_hits": 9,
    "credential_hits": 11,
    "generic_greeting": 8,
    "shouting": 3,
    "exclamations": 2,
}

VERDICTS = [(70, "phishing"), (40, "suspicious"), (0, "likely_safe")]


def score(url=None, text=None):
    """Score a URL and/or email body. Returns an explainable verdict dict."""
    feats = {}
    reasons = []

    if url:
        uf, ur = url_features(url)
        feats.update(uf)
        reasons += ur
    if text:
        tf, tr = text_features(text)
        feats.update(tf)
        reasons += tr

    total = 0
    contributions = {}
    for key, weight in WEIGHTS.items():
        val = feats.get(key, 0)
        if val:
            pts = min(weight * val, weight * 3)
            contributions[key] = pts
            total += pts

    if not feats.get("https", 1):
        total += 6
        contributions["no_https"] = 6

    total = min(100, total)
    verdict = next(v for threshold, v in VERDICTS if total >= threshold)

    return {
        "score": total,
        "verdict": verdict,
        "reasons": reasons,
        "contributions": dict(sorted(contributions.items(),
                                     key=lambda kv: -kv[1])),
        "features": feats,
    }
