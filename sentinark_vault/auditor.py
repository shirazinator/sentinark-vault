"""
Sentinark-Vault: Central Audit Engine
Combines Entropy, k-Anonymity HIBP breach check, Hardware Crack Simulation,
and Pattern Analysis into a unified security dossier.
"""

from typing import Dict, Any
from .entropy import calculate_entropy
from .crack_simulator import simulate_crack_times
from .pwned_checker import check_pwned_hash
from .pattern_detector import detect_patterns
from .generator import generate_secure_password, generate_passphrase


def audit_password(password: str, check_breaches: bool = True) -> Dict[str, Any]:
    """
    Performs a comprehensive, non-blocking security audit of a password.
    
    100% Zero-Knowledge: Plaintext password is NEVER sent over any network.
    Zero CPU freeze: Simulations use closed-form mathematical formulas.
    """
    entropy_info = calculate_entropy(password)
    pattern_info = detect_patterns(password)
    crack_sim = simulate_crack_times(entropy_info["length"], entropy_info["charset_size"])

    pwned_info = {"pwned": False, "count": 0, "status": "skipped", "message": "Breach check disabled"}
    if check_breaches and password:
        pwned_info = check_pwned_hash(password)

    # Calculate overall security score (0 - 100)
    raw_score = min(entropy_info["entropy_bits"], 100.0)
    # Deduct penalty from heuristic patterns
    final_score = max(0, raw_score - pattern_info["penalty"])

    # If password is known to be pwned in data breaches, cap score drastically
    if pwned_info.get("pwned", False):
        final_score = min(final_score, 10.0)

    # Produce actionable recommendations
    recommendations = []
    if pwned_info.get("pwned", False):
        recommendations.append("CHANGE IMMEDIATELY: This password exists in publicly dumped data breaches!")
    if entropy_info["length"] < 14:
        recommendations.append("Increase length to at least 14-16 characters.")
    if not (entropy_info["has_lower"] and entropy_info["has_upper"] and entropy_info["has_digits"] and entropy_info["has_symbols"]):
        recommendations.append("Mix uppercase, lowercase, numbers, and special symbols to expand keyspace.")
    for vuln in pattern_info["vulnerabilities"]:
        recommendations.append(f"Remove structural weakness: {vuln}")

    # Generate suggested strong replacements
    suggested_pass = generate_secure_password(length=18)
    suggested_phrase = generate_passphrase(num_words=5)

    return {
        "score": round(final_score, 1),
        "entropy": entropy_info,
        "patterns": pattern_info,
        "breach_audit": pwned_info,
        "crack_simulation": crack_sim,
        "recommendations": recommendations,
        "suggested_replacements": {
            "complex": suggested_pass,
            "passphrase": suggested_phrase
        }
    }
