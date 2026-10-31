"""
Sentinark-Vault: Mathematical Information Entropy & Keyspace Analysis
Calculates information entropy (bits) and combinatorial search space.
Zero CPU lag - pure O(1) mathematical modeling.
"""

import math
from typing import Dict, Any


def calculate_entropy(password: str) -> Dict[str, Any]:
    """
    Computes Shannon entropy and combinatorial keyspace for a given password.
    
    Formula:
    - Combinatorial Keyspace (S): R^L (R = charset size, L = password length)
    - Information Entropy (E): L * log2(R)
    - Shannon Entropy (H): - sum(p_i * log2(p_i))
    """
    if not password:
        return {
            "length": 0,
            "charset_size": 0,
            "entropy_bits": 0.0,
            "shannon_entropy": 0.0,
            "keyspace_scientific": "0",
            "has_lower": False,
            "has_upper": False,
            "has_digits": False,
            "has_symbols": False,
            "strength_level": "None"
        }

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    # Symbols: anything not alphanumeric or space, plus special chars
    has_symbols = any(not c.isalnum() for c in password)

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digits:
        charset_size += 10
    if has_symbols:
        charset_size += 33  # Standard ASCII printable symbols

    charset_size = max(charset_size, 1)

    # Combinatorial entropy in bits: L * log2(R)
    entropy_bits = length * math.log2(charset_size)

    # Shannon character distribution entropy: - sum(p * log2(p))
    frequency = {}
    for char in password:
        frequency[char] = frequency.get(char, 0) + 1

    shannon = 0.0
    for count in frequency.values():
        p = count / length
        shannon -= p * math.log2(p)

    # Keyspace in scientific notation (avoid floating point overflow on huge numbers)
    # S = R^L => log10(S) = L * log10(R)
    log10_keyspace = length * math.log10(charset_size)
    exponent = int(math.floor(log10_keyspace))
    mantissa = 10 ** (log10_keyspace - exponent)
    keyspace_scientific = f"{mantissa:.2f} × 10^{exponent}" if exponent > 0 else f"{int(mantissa)}"

    # Determine strength category based on NIST / OWASP guidelines
    if entropy_bits < 28:
        strength_level = "Very Weak"
    elif entropy_bits < 36:
        strength_level = "Weak"
    elif entropy_bits < 60:
        strength_level = "Reasonable"
    elif entropy_bits < 80:
        strength_level = "Strong"
    else:
        strength_level = "Very Strong"

    return {
        "length": length,
        "charset_size": charset_size,
        "entropy_bits": round(entropy_bits, 2),
        "shannon_entropy": round(shannon, 3),
        "keyspace_scientific": keyspace_scientific,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "strength_level": strength_level
    }
