<div align="center">

# phish-lens

**Explainable phishing scorer for URLs and email bodies.**

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00FF9C?style=flat-square)
![Explainable](https://img.shields.io/badge/Explainable-AI-A855F7?style=flat-square)
![Dependencies](https://img.shields.io/badge/dependencies-none-00D9FF?style=flat-square)
![tests](https://github.com/anonymoustest137/phish-lens/actions/workflows/tests.yml/badge.svg)

</div>

---

## What is this?

**phish-lens decides whether a link or an email is trying to scam you — and tells you why.**

Phishing is the single most common way organisations get breached. An attacker sends an
email that looks like it came from PayPal, Microsoft or your own IT department, containing a
link to a fake login page. You type your password into their site, and they now have your
credentials.

It works because a convincing fake is cheap to produce and humans are bad at scrutinising
URLs. phish-lens automates that scrutiny.

### The problem it solves

Most phishing filters output a single number: `0.87`. Is that a phish? Why? Nobody knows —
the model won't say.

That's a real operational problem:

- A SOC analyst can't triage a score they can't interpret
- A user told "this is suspicious" with no reason learns nothing
- When the filter is wrong, you can't tell *why* it was wrong, so you can't fix it

**phish-lens is explainable by construction.** Every verdict lists the exact signals that
produced it:

```
[##################................] 55/100
verdict: SUSPICIOUS

why:
  - High-risk TLD: .xyz
  - High-entropy hostname (possible DGA)
  - No HTTPS
  - Impersonates brand 'paypal' outside its real domain
```

An analyst reads that in two seconds and makes a decision. A user reads it and learns what
to look for next time.

### Who it's for

- **SOC analysts** triaging reported phishing emails
- **Email security teams** prototyping detection logic
- **Security awareness trainers** demonstrating *why* a link is dangerous
- **Developers** adding a pre-send URL check to an application
- **Students** learning what actually distinguishes a malicious URL

---

## How it works

phish-lens extracts measurable features, assigns each a weight, and sums them into a 0–100
score. No training data, no model file, no opaque inference — just transparent arithmetic.

```
URL and/or email text
        |
        v
[1] FEATURE EXTRACTION   -> 14 URL signals + 6 text signals
        |
        v
[2] WEIGHTED SCORING     -> each signal contributes fixed points
        |
        v
[3] VERDICT BANDING      -> phishing / suspicious / likely_safe
        |
        v
    score + reasons
```

### URL features

| Feature | Weight | Why it signals phishing |
|---|---|---|
| Raw IP as host | 25 | Legitimate businesses use domain names, not `http://192.168.1.50/login` |
| Brand in wrong domain | 22 | `paypal.secure-login.xyz` is not PayPal — the real domain is the *last* part |
| `@` in URL | 20 | Everything before `@` is ignored by browsers: `google.com@evil.tld` goes to **evil.tld** |
| High-risk TLD | 18 | `.zip`, `.mov`, `.tk`, `.xyz` are cheap/free and heavily abused |
| URL shortener | 12 | Hides the true destination until you've already clicked |
| Subdomain depth | 5 each | `login.secure.account.verify.evil.com` fakes legitimacy through length |
| Hyphens in host | 4 each | `pay-pal-secure-login.com` mimics a brand |
| No HTTPS | 6 | Credential forms over plain HTTP are indefensible in 2026 |
| Shannon entropy | flag | Randomised hostnames suggest algorithmic generation |

#### On entropy

**Shannon entropy** measures randomness in a string. A human-chosen domain like
`github` scores low — it's pronounceable, with repeated common letters. A machine-generated
domain like `x7fq2kzp9mw` scores high.

Malware uses **DGAs** (Domain Generation Algorithms) to create thousands of random domains
so defenders can't block them all in advance. High entropy in a hostname is a strong hint
you're looking at one.

```python
shannon_entropy("aaaa")     # 0.0   — no randomness
shannon_entropy("ab3x9zq")  # 2.8   — high randomness
```

### Email text features

| Feature | Weight | Why it signals phishing |
|---|---|---|
| Credential requests | 11 each | Real companies don't email asking for your password |
| Urgency language | 9 each | "Act now", "suspended", "within 24 hours" — panic defeats judgement |
| Generic greeting | 8 | "Dear Customer" means they don't know your name |
| ALL-CAPS words | 3 each | Manufactured alarm |
| Excessive `!` | 2 each | Rare in genuine corporate mail |

Urgency is the key psychological lever in nearly every phishing campaign. The message must
stop you from thinking — which is why "your account will be suspended in 24 hours" appears
so often.

### Verdict bands

| Score | Verdict | Recommended action |
|---|---|---|
| 70–100 | `phishing` | Block and report |
| 40–69 | `suspicious` | Manual review |
| 0–39 | `likely_safe` | Allow |

---

## Install

```bash
git clone https://github.com/anonymoustest137/phish-lens.git
cd phish-lens
pip install -r requirements.txt   # only pytest, for the test suite
```

**No runtime dependencies** — standard library only.

---

## Usage

```bash
# score a URL
python -m phishlens.cli -u "http://paypal.secure-login.xyz/verify"

# score an email body
python -m phishlens.cli -f suspicious_email.txt

# score both together
python -m phishlens.cli -u "http://bit.ly/x" -f mail.txt

# JSON output for automation
python -m phishlens.cli -u "http://bit.ly/x" --json

# pipe from stdin
cat email.txt | python -m phishlens.cli -f -
```

### Options

| Flag | Description |
|---|---|
| `-u`, `--url` | URL to analyze |
| `-f`, `--file` | Email body file (`-` for stdin) |
| `--json` | Emit full JSON including feature values |
| `--version` | Print version and exit |

### JSON output

```json
{
  "score": 55,
  "verdict": "suspicious",
  "reasons": [
    "High-risk TLD: .xyz",
    "Impersonates brand 'paypal' outside its real domain"
  ],
  "contributions": { "brand_in_subdomain": 22, "suspicious_tld": 18 },
  "features": { "url_length": 48, "has_ip": 0, "entropy": 4.02 }
}
```

`contributions` is sorted by impact, so the top entry is the biggest reason for the score.

---

## Project structure

| Path | Purpose |
|---|---|
| `phishlens/features.py` | URL and text feature extraction, entropy calculation |
| `phishlens/scorer.py` | Weighting, scoring and verdict banding |
| `phishlens/cli.py` | Command line entry point |
| `tests/test_scorer.py` | pytest suite |

### Using it as a library

```python
from phishlens.scorer import score

result = score(url="http://paypal.secure-login.xyz/verify")

if result["verdict"] == "phishing":
    quarantine(message)
    log_reasons(result["reasons"])
```

---

## Design notes

**Why not machine learning?** A trained classifier would likely score a few points higher on
a benchmark — but it needs labelled training data, a model file, a retraining pipeline, and
it cannot explain itself. For a triage tool where an analyst must justify a decision,
explainability beats marginal accuracy.

The feature extraction here is also exactly what you'd feed *into* an ML model. This repo is
a usable tool and a sound foundation for a learned one.

**Weights are tunable.** They live in a single dict in `scorer.py`. Adjust them to your own
false-positive tolerance — a bank and a university have very different thresholds.

**Capped contributions.** Each feature contributes at most 3× its weight, so one repeated
signal can't dominate the score.

---

## Limitations

Be aware of what this does *not* do:

- **No page fetching.** phish-lens never visits the URL, so it can't detect a malicious page
  behind a clean-looking link. That's deliberate — fetching alerts the attacker and risks
  executing hostile content.
- **No reputation data.** There's no blocklist or threat-intel lookup. A brand-new phishing
  domain with a clean URL structure will score low.
- **Heuristics can be gamed.** An attacker who knows these rules can craft a URL that avoids
  them. Use this as one layer, not your only defence.
- **English-centric text analysis.** The urgency and credential keyword lists are English.

---

## Tests

```bash
pytest -q
```

Six tests cover clean URLs, IP-based URLs, brand impersonation, urgent email text, entropy
calculation and reason generation. CI runs against Python 3.10 and 3.12.

---

## Roadmap

- [ ] Homograph / punycode detection (`аpple.com` with a Cyrillic `а`)
- [ ] Levenshtein distance against a brand domain list
- [ ] Optional WHOIS domain-age lookup
- [ ] Attachment and MIME analysis
- [ ] Multi-language keyword sets

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built by [@anonymoustest137](https://github.com/anonymoustest137) · [Portfolio](https://anonymoustest137.github.io/anonymoustest137/)

 *For educational and authorized testing purposes only.*

</div>
