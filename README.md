<div align="center">

# 🔐 PwEntropyChecker

### Password Strength Analyzer — Built on Real Security Engineering, Not Regex Box-Ticking

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![HIBP](https://img.shields.io/badge/HaveIBeenPwned-API-red?style=flat-square)](https://haveibeenpwned.com/API/v3)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#license)
[![NIST](https://img.shields.io/badge/NIST-800--63B%20Aligned-blue?style=flat-square)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-SamSec404-red?style=flat-square&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/SamSec404)

*Shannon entropy scoring · Attack pattern detection · Live breach checking via k-anonymity*

</div>

---

## 📖 Table of Contents

- [Why This Exists](#-why-this-exists)
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [The Security Concepts, Explained](#-the-security-concepts-explained)
- [Roadmap](#-roadmap)
- [License](#-license)
- [Author](#-author)

---

## 💡 Why This Exists

Most "password strength checker" tutorials count rule-matches — *has an
uppercase letter? has a number?* That approach is genuinely misleading:
a password like `P@ssw0rd1` ticks every box on a typical checklist, yet
it's cracked in seconds because it's a well-known substitution pattern
sitting in every attacker's dictionary.

**PwEntropyChecker measures actual resistance to attack**, using the same
principles real security tooling uses: entropy, pattern analysis, and
live breach intelligence — not arbitrary checkboxes.

---

## ✨ Features

| | |
|---|---|
| 🎲 **Entropy Scoring** | Calculates true randomness (bits of entropy) from character pool size × length, instead of counting rule-matches |
| 🕵️ **Pattern Attack Detection** | Flags keyboard walks (`qwerty`), sequences (`1234`), repeats (`aaaa`), and l33t-speak dictionary matches (`p@ssw0rd` → `password`) |
| ⏱️ **Crack-Time Estimation** | Projects realistic time-to-crack across 4 attack speeds — throttled login, unthrottled API, offline slow hash, offline GPU hash |
| 🚨 **Live Breach Check** | Checks against 800M+ real breached passwords via HaveIBeenPwned, using the **k-anonymity model** so the password is never fully exposed over the network |
| 📐 **NIST SP 800-63B Aligned** | Favors length over arbitrary complexity rules; treats breach exposure as automatically disqualifying, per current federal guidance |
| ⚡ **Real-Time UI** | Debounced live feedback as you type — entropy, crack times, pattern warnings, and breach status update instantly |

---

## 🏗️ Architecture

```
┌──────────────────┐        POST /check         ┌───────────────────────┐        k-anonymity request        ┌────────────────────┐
│                  │  ───────────────────────►  │                       │  ─────────────────────────────►  │                    │
│   frontend.html  │                             │   FastAPI Backend     │                                    │  HaveIBeenPwned API │
│   (UI/UX layer)  │  ◄───────────────────────  │  entropy · patterns · │  ◄─────────────────────────────  │  (breach lookup)     │
│                  │      JSON verdict           │  scoring logic        │      matching hash suffixes       │                    │
└──────────────────┘                             └───────────────────────┘                                    └────────────────────┘
```

The backend never transmits the plaintext password or its full hash to any
third party — only the first 5 characters of a SHA-1 hash are sent to HIBP,
and the real comparison happens locally. See [below](#-the-security-concepts-explained)
for why that matters.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, FastAPI, httpx
- **Frontend:** Vanilla HTML/CSS/JS (no framework overhead, fully portable)
- **External API:** HaveIBeenPwned Pwned Passwords (k-anonymity endpoint)
- **Standards Reference:** NIST SP 800-63B Digital Identity Guidelines

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/SamSec404/PwEntropyChecker.git
cd PwEntropyChecker/backend
pip install -r requirements.txt
```

### Run the backend

```bash
uvicorn main:app --reload --port 8000
```

### Run the frontend

Just open `frontend.html` in your browser — no build step required.

---

## 📡 API Reference

### `POST /check`

**Request**
```json
{ "password": "Tr0ub4dor&3" }
```

**Response**
```json
{
  "entropy_bits": 72.1,
  "crack_times": {
    "online_throttled (100/hr)": "1.2e+15 years",
    "online_unthrottled (10/sec)": "4.3e+11 years",
    "offline_slow_hash (10k/sec)": "4.3e+8 years",
    "offline_fast_hash (10B/sec)": "1.5 years"
  },
  "patterns_detected": [],
  "breach_count": 0,
  "verdict": {
    "label": "Strong",
    "score": 72.1,
    "color": "#3fb950"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `entropy_bits` | float | Shannon entropy in bits |
| `crack_times` | object | Estimated crack time at 4 attack speeds |
| `patterns_detected` | array | Human-readable list of weak patterns found |
| `breach_count` | int | Times seen in known breaches (`-1` = HIBP unreachable) |
| `verdict` | object | Overall label, numeric score, and UI color |

---

## 🔬 The Security Concepts, Explained

<details>
<summary><strong>Shannon Entropy Scoring</strong></summary>

<br>

Entropy is calculated as:

```
entropy_bits = password_length × log2(character_pool_size)
```

Where `character_pool_size` grows based on which character classes are
actually present (lowercase = +26, uppercase = +26, digits = +10, symbols
≈ +32). This rewards genuine unpredictability rather than "did you follow
the rules."

</details>

<details>
<summary><strong>Pattern Attack Detection</strong></summary>

<br>

Inspired by Dropbox's `zxcvbn` algorithm. Detects:
- Repeated characters (`aaa`, `111`)
- Sequential runs (`abcd`, `1234`, and reversed)
- Keyboard walks (`qwerty`, `asdfgh`)
- Dictionary matches after normalizing l33t-speak substitutions
- Predictable "word + digits" patterns (`admin2023`)

</details>

<details>
<summary><strong>k-Anonymity Breach Checking</strong></summary>

<br>

To check a password against HaveIBeenPwned's breach database **without
ever exposing the actual password**:

1. The password is hashed locally with SHA-1.
2. Only the **first 5 characters** of that hash are sent to the HIBP API.
3. HIBP returns *every* hash suffix sharing that prefix (typically 500+ results).
4. The full match happens **locally** — HIBP never sees the complete hash,
   let alone the plaintext password.

This is the same privacy-preserving technique used by Chrome's and
Firefox's built-in breached-password warnings.

</details>

<details>
<summary><strong>NIST SP 800-63B Alignment</strong></summary>

<br>

Current NIST guidance moved away from forced complexity rules (mandatory
symbols, periodic rotation) toward:
- Favoring **length** over arbitrary character-class requirements
- Checking new passwords against **known breach/dictionary lists**
- Treating a breached password as disqualifying regardless of "complexity"

PwEntropyChecker's scoring logic follows this — a long, breached password is
capped as weak even if its entropy score looks decent.

</details>

---

## 🗺️ Roadmap

- [ ] Swap demo word list for full `rockyou.txt` top-10k
- [ ] Add API rate limiting
- [ ] Dockerize for one-command deployment
- [ ] pytest coverage for entropy/pattern edge cases
- [ ] Live deployment (Render/Railway backend + GitHub Pages frontend)

---

## 📄 License

MIT — free to use, modify, and learn from.

---

## 👤 Author

**Muhammad — SamSec404**
CS Student · Cybersecurity & Automation

[![GitHub](https://img.shields.io/badge/GitHub-SamSec404-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/SamSec404)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muhammad%20Sanaullah-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/malik-muhammad-sanaullah-050m1y05f48/)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-SamSec404-212C42?style=for-the-badge&logo=tryhackme&logoColor=red)](https://tryhackme.com/p/SamSec404)

</div>
