"""
Sentinark-Vault: Heuristic Pattern & Dictionary Vulnerability Detector
Finds predictable patterns, keyboard walks, leetspeak, and common passwords.
"""

import re
from typing import Dict, List, Any

# Top notorious dictionary passwords and root words
TOP_COMMON_ROOTS = {
    "password", "123456", "12345678", "123456789", "qwerty", "admin", "welcome",
    "login", "user", "guest", "root", "default", "secret", "master", "football",
    "monkey", "dragon", "baseball", "shadow", "superman", "batman", "trustno1",
    "iloveyou", "princess", "sunshine", "starwars", "pass123", "letmein"
}

KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "abcdefghijklmnopqrstuvwxyz"
]

LEET_MAP = {
    "@": "a", "4": "a",
    "8": "b",
    "(": "c", "<": "c",
    "3": "e",
    "6": "g", "9": "g",
    "#": "h",
    "1": "i", "!": "i", "|": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t", "+": "t",
    "2": "z"
}


def normalize_leetspeak(text: str) -> str:
    """Translates common leetspeak substitutions back into base letters."""
    lowered = text.lower()
    chars = []
    for c in lowered:
        chars.append(LEET_MAP.get(c, c))
    return "".join(chars)


def detect_patterns(password: str) -> Dict[str, Any]:
    """
    Analyzes password for structural weaknesses, dictionary matches,
    keyboard walks, repeated chars, and dates.
    """
    vulnerabilities: List[str] = []
    score_penalty = 0

    if not password:
        return {"vulnerabilities": ["Empty password"], "normalized": "", "is_vulnerable": True}

    lowered = password.lower()
    normalized = normalize_leetspeak(password)

    # 1. Exact or Substring Common Root Check
    for root in TOP_COMMON_ROOTS:
        if root in lowered or root in normalized:
            vulnerabilities.append(f"Contains common dictionary word or pattern: '{root}'")
            score_penalty += 35
            break

    # 2. Sequential Characters / Keyboard Walks
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 2):
            sub = seq[i:i+3]
            sub_rev = sub[::-1]
            if sub in lowered or sub in normalized or sub_rev in lowered:
                vulnerabilities.append(f"Contains sequential pattern / keyboard walk: '{sub}'")
                score_penalty += 20
                break

    # 3. Repeated Characters (e.g., 'aaa', '1111')
    repeat_match = re.search(r"(.)\1{2,}", password)
    if repeat_match:
        vulnerabilities.append(f"Contains repetitive characters: '{repeat_match.group(0)}'")
        score_penalty += 15

    # 4. Year Detection (1950 - 2035)
    year_match = re.search(r"(19\d{2}|20[0-3]\d)", password)
    if year_match:
        vulnerabilities.append(f"Appears to include a birth or calendar year: '{year_match.group(0)}'")
        score_penalty += 15

    # 5. Short Length Penalty
    if len(password) < 8:
        vulnerabilities.append("Critically short length (< 8 characters)")
        score_penalty += 40
    elif len(password) < 12:
        vulnerabilities.append("Sub-optimal length (< 12 characters; modern recommendations require 14+)")
        score_penalty += 15

    # 6. Single Charset Only
    if password.isalpha():
        vulnerabilities.append("Composed entirely of letters (no numbers or symbols)")
        score_penalty += 15
    elif password.isdigit():
        vulnerabilities.append("Composed entirely of numbers (trivial PIN)")
        score_penalty += 35

    return {
        "vulnerabilities": vulnerabilities,
        "penalty": min(score_penalty, 90),
        "normalized": normalized,
        "is_vulnerable": len(vulnerabilities) > 0
    }
