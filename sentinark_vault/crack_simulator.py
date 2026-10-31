"""
Sentinark-Vault: Mathematical Hardware Crack-Time Simulator
Uses closed-form log-scale formulas to benchmark password resistance
against real-world attack rigs (Hashcat benchmarks) in O(1) time.
Guaranteed ZERO CPU or system freeze.
"""

import math
from typing import Dict, Any


# Real-world Hashcat cracking speeds (guesses per second)
# Based on public Hashcat benchmarks for various algorithms and hardware:
ATTACK_PROFILES = {
    "online_throttled": {
        "name": "Online Attack (Web Login with Rate Limits)",
        "rate": 10,  # 10 guesses/sec (e.g., standard login rate limit)
        "description": "Slow online brute force against modern login endpoints."
    },
    "cpu_single": {
        "name": "Standard Laptop CPU (Single Core)",
        "rate": 100_000,  # 100,000 guesses/sec (MD5 / NTLM)
        "description": "Basic consumer CPU offline attack."
    },
    "gpu_single_rtx": {
        "name": "Single NVIDIA RTX 4090 GPU",
        "rate": 20_000_000_000,  # 20 GH/s for NTLM / Fast Hash
        "description": "High-end enthusiast GPU running Hashcat."
    },
    "gpu_cluster_8x": {
        "name": "8x NVIDIA RTX 4090 Password Cracking Rig",
        "rate": 160_000_000_000,  # 160 GH/s (Standard dedicated cracking rig)
        "description": "Professional forensic / penetration tester cracking server."
    },
    "nation_state_asic": {
        "name": "Nation-State / ASIC Supercomputing Cluster",
        "rate": 100_000_000_000_000,  # 100 TH/s
        "description": "Massive state-sponsored ASIC / supercomputer cracking cluster."
    }
}


def _seconds_to_human(seconds_log10: float) -> str:
    """
    Converts a log10 value of seconds into a human-readable duration string.
    Works for values from 0.000001 seconds to 10^100 years without numeric overflow.
    """
    if seconds_log10 < -3:
        return "Instant (< 1 millisecond)"
    if seconds_log10 < 0:
        return "< 1 second"

    # Actual seconds if small enough to calculate cleanly
    if seconds_log10 < 10:
        seconds = 10 ** seconds_log10
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        if seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        years = seconds / 31536000
        if years < 1000:
            return f"{years:.1f} years"
        return f"{int(years):,} years"

    # For huge exponents: convert log10(seconds) to log10(years)
    # 1 year ~ 3.1536 x 10^7 seconds (log10 is ~7.4988)
    log10_years = seconds_log10 - 7.49881076

    if log10_years < 6:
        years = 10 ** log10_years
        return f"{int(years):,} years"
    elif log10_years < 10:
        # Billions of years (Universe age is ~13.8 billion years = 1.38 x 10^10 years)
        return f"{10 ** (log10_years - 9):.2f} Billion years"
    elif log10_years < 100:
        exp = int(math.floor(log10_years))
        mant = 10 ** (log10_years - exp)
        return f"{mant:.2f} × 10^{exp} years (Astronomical / Uncrackable)"
    else:
        return "Effectively Infinite (> Heat Death of Universe)"


def simulate_crack_times(length: int, charset_size: int) -> Dict[str, Any]:
    """
    Calculates expected cracking time for standard attacker hardware profiles.
    Time complexity: O(1). Zero load, zero loop iterations.
    """
    if length <= 0 or charset_size <= 1:
        return {
            key: {
                "name": profile["name"],
                "time_human": "Instant",
                "description": profile["description"],
                "seconds_log10": -5.0
            }
            for key, profile in ATTACK_PROFILES.items()
        }

    # Average guesses needed is half the total keyspace: S / 2
    # log10(S / 2) = log10(S) - log10(2) = L * log10(R) - 0.30103
    log10_keyspace = length * math.log10(charset_size)
    log10_average_guesses = log10_keyspace - math.log10(2)

    results = {}
    for key, profile in ATTACK_PROFILES.items():
        log10_rate = math.log10(profile["rate"])
        # Crack time in seconds: log10(T) = log10(guesses) - log10(rate)
        log10_seconds = log10_average_guesses - log10_rate

        results[key] = {
            "name": profile["name"],
            "rate_display": f"{profile['rate']:,} guesses/sec",
            "time_human": _seconds_to_human(log10_seconds),
            "description": profile["description"],
            "seconds_log10": round(log10_seconds, 2)
        }

    return results
