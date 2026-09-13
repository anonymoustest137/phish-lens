import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishlens.scorer import score
from phishlens.features import url_features, shannon_entropy


def test_clean_url_is_safe():
    r = score(url="https://github.com/anonymoustest137")
    assert r["verdict"] == "likely_safe"
    assert r["score"] < 40


def test_ip_url_flagged():
    r = score(url="http://192.168.1.50/paypal/login.php")
    assert r["features"]["has_ip"] == 1
    assert r["score"] >= 40


def test_brand_impersonation():
    r = score(url="http://paypal.secure-login.xyz/verify")
    assert r["verdict"] in ("phishing", "suspicious")
    assert any("paypal" in x.lower() for x in r["reasons"])


def test_urgent_email_text():
    body = ("Dear Customer, URGENT: your account will be suspended. "
            "Verify your account immediately and confirm your password!!!")
    r = score(text=body)
    assert r["score"] > 0
    assert r["features"]["generic_greeting"] == 1


def test_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab3x9zq") > 2.0


def test_reasons_are_explainable():
    r = score(url="http://bit.ly/x@evil")
    assert isinstance(r["reasons"], list)
    assert len(r["reasons"]) > 0
