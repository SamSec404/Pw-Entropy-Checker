"""
Password Strength Checker API
------------------------------
Real security engineering, not just regex box-ticking:
  - Shannon-entropy based strength scoring
  - Pattern attack detection (keyboard walks, sequences, repeats, l33t-speak)
  - Have I Been Pwned breach check via k-anonymity (password never leaves
    your machine in plaintext or even as a full hash)
  - NIST SP 800-63B aligned guidance (length > arbitrary complexity rules)

Run:
    pip install fastapi uvicorn httpx --break-system-packages
    uvicorn main:app --reload --port 8000
"""

import hashlib
import math
import re
from typing import List

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Password Strength Checker API")

# Allow the frontend (served from file:// or any localhost port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------
# Common password list (small sample — swap in rockyou.txt top-10k for real use)
# --------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "12345678", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "123123", "000000", "password123",
    "qwerty123", "1q2w3e4r", "sunshine", "princess", "trustno1",
}

# Keyboard rows used to detect walking patterns like "qwerty" or "asdfgh"
KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Common l33t-speak substitutions, used to normalize before dictionary checks
LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
})


class PasswordRequest(BaseModel):
    password: str


# --------------------------------------------------------------------------
# Entropy calculation
# --------------------------------------------------------------------------
def calculate_entropy(pwd: str) -> float:
    """
    Shannon-style entropy: bits = length * log2(pool_size)
    pool_size = size of the character set the password actually draws from.
    This rewards TRUE randomness/length over arbitrary rule-following.
    """
    pool = 0
    if re.search(r"[a-z]", pwd):
        pool += 26
    if re.search(r"[A-Z]", pwd):
        pool += 26
    if re.search(r"[0-9]", pwd):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pwd):
        pool += 32  # approx printable special chars

    if pool == 0 or len(pwd) == 0:
        return 0.0

    return round(len(pwd) * math.log2(pool), 2)


def estimate_crack_times(entropy: float) -> dict:
    """
    Translate entropy into human-readable crack time estimates
    at different attack speeds.
    """
    guesses = 2 ** entropy / 2  # average case, not worst case

    speeds = {
        "online_throttled (100/hr)": 100 / 3600,       # login form w/ rate limiting
        "online_unthrottled (10/sec)": 10,             # weakly protected API
        "offline_slow_hash (10k/sec)": 10_000,          # bcrypt/scrypt
        "offline_fast_hash (10B/sec)": 10_000_000_000,  # raw MD5/SHA1 on GPU
    }

    results = {}
    for label, speed in speeds.items():
        seconds = guesses / speed
        results[label] = human_time(seconds)
    return results


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_secs in units:
        if seconds >= unit_secs:
            value = seconds / unit_secs
            if value > 1000:
                return f"{value:.2e} {name}"
            return f"{value:.1f} {name}"
    return "instantly"


# --------------------------------------------------------------------------
# Pattern detection (zxcvbn-inspired, simplified)
# --------------------------------------------------------------------------
def detect_patterns(pwd: str) -> List[str]:
    warnings = []
    lower = pwd.lower()

    # Repeated characters: aaaa, 1111
    if re.search(r"(.)\1{2,}", pwd):
        warnings.append("Contains repeated characters (e.g. 'aaa', '111')")

    # Sequential characters: abcd, 1234, or reverse
    if has_sequential_run(lower, 4):
        warnings.append("Contains a sequential run (e.g. 'abcd', '1234')")

    # Keyboard walk detection
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in lower or chunk[::-1] in lower:
                warnings.append(f"Contains a keyboard-walk pattern ('{chunk}')")
                break

    # Dictionary check, including l33t-speak normalization
    normalized = lower.translate(LEET_MAP)
    if lower in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS:
        warnings.append("Matches a known common password (dictionary attack risk)")

    # Simple word + digits pattern, e.g. "password1", "admin2023"
    if re.match(r"^[a-zA-Z]+\d{1,4}$", pwd):
        word_part = re.match(r"^[a-zA-Z]+", pwd).group().lower()
        if word_part in COMMON_PASSWORDS or len(word_part) < 8:
            warnings.append("Follows predictable 'word + digits' pattern")

    return warnings


def has_sequential_run(s: str, run_length: int) -> bool:
    sequences = "abcdefghijklmnopqrstuvwxyz0123456789"
    rev = sequences[::-1]
    for seq in (sequences, rev):
        for i in range(len(seq) - run_length + 1):
            if seq[i:i + run_length] in s:
                return True
    return False


# --------------------------------------------------------------------------
# Have I Been Pwned check (k-anonymity model)
# --------------------------------------------------------------------------
async def check_hibp(pwd: str) -> int:
    """
    Sends only the first 5 characters of the SHA-1 hash to HIBP's API.
    HIBP returns all hash suffixes matching that prefix; we compare locally.
    The full password NEVER leaves this server, and not even the full hash does.
    Returns the number of times this password has appeared in known breaches.
    """
    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            resp.raise_for_status()
    except httpx.HTTPError:
        return -1  # signal "couldn't check" rather than false "safe"

    for line in resp.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return int(count)
    return 0


# --------------------------------------------------------------------------
# Overall scoring
# --------------------------------------------------------------------------
def overall_verdict(entropy: float, pattern_count: int, breach_count: int) -> dict:
    score = entropy
    score -= pattern_count * 15   # each detected weak pattern is a heavy penalty
    if breach_count > 0:
        score = min(score, 20)   # breached password is capped as very weak, period

    if score < 28:
        label, color = "Very Weak", "#f85149"
    elif score < 40:
        label, color = "Weak", "#db6d28"
    elif score < 60:
        label, color = "Fair", "#d29922"
    elif score < 80:
        label, color = "Strong", "#3fb950"
    else:
        label, color = "Very Strong", "#2ea043"

    return {"label": label, "color": color, "score": round(max(score, 0), 1)}


@app.post("/check")
async def check_password(req: PasswordRequest):
    pwd = req.password

    if not pwd:
        return {"error": "empty password"}

    entropy = calculate_entropy(pwd)
    patterns = detect_patterns(pwd)
    crack_times = estimate_crack_times(entropy)
    breach_count = await check_hibp(pwd)
    verdict = overall_verdict(entropy, len(patterns), breach_count)

    return {
        "entropy_bits": entropy,
        "crack_times": crack_times,
        "patterns_detected": patterns,
        "breach_count": breach_count,
        "verdict": verdict,
    }


@app.get("/")
def root():
    return {"status": "ok", "message": "POST a password to /check"}
