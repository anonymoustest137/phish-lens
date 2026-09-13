<div align="center">

# 🎣 phish-lens

**Explainable phishing scorer for URLs and email bodies.**

![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white) ![MIT](https://img.shields.io/badge/License-MIT-00FF9C?style=flat-square) ![Explainable](https://img.shields.io/badge/Explainable-AI-A855F7?style=flat-square)

![tests](https://github.com/anonymoustest137/phish-lens/actions/workflows/tests.yml/badge.svg)

</div>

---

## Overview

phish-lens scores URLs and email text for phishing risk using a weighted feature model. Every verdict ships with the human-readable reasons behind it — no opaque black-box score.

## Features

- **14 URL features** including raw-IP hosts, `@` obfuscation, risky TLDs, shorteners and Shannon entropy
- **Brand-impersonation detection** for 8 commonly spoofed brands
- **Email body analysis** for urgency language, credential requests and generic greetings
- **Fully explainable** — each score lists the exact signals that produced it
- **Weighted scoring** with a 0–100 scale and three verdict bands

## Install

```bash
git clone https://github.com/anonymoustest137/phish-lens.git
cd phish-lens
pip install -r requirements.txt   # only pytest, for the test suite
```

## Usage

```bash
# score a URL
python -m phishlens.cli -u "http://paypal.secure-login.xyz/verify"

# score an email body
python -m phishlens.cli -f suspicious_email.txt

# both, as JSON
python -m phishlens.cli -u "http://bit.ly/x" -f mail.txt --json
```

## Project structure

| Path | Purpose |
|---|---|
| `phishlens/features.py` | URL and text feature extraction |
| `phishlens/scorer.py` | weighted scoring and verdicts |
| `phishlens/cli.py` | command line entry point |

## Example output

```
phish-lens v0.1.0
target: http://paypal.secure-login.xyz/verify-account-now
[##################................] 55/100
verdict: SUSPICIOUS

why:
  - High-risk TLD: .xyz
  - High-entropy hostname (possible DGA)
  - No HTTPS
  - Impersonates brand 'paypal' outside its real domain
```

## Verdict bands

| Score | Verdict |
|---|---|
| 70–100 | `phishing` |
| 40–69 | `suspicious` |
| 0–39 | `likely_safe` |

## Tests

```bash
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built by [@anonymoustest137](https://github.com/anonymoustest137) · [Portfolio](https://anonymoustest137.github.io/anonymoustest137/)

⚠️ *For educational and authorized testing purposes only.*

</div>