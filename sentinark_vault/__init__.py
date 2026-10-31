"""
Sentinark-Vault: Zero-Knowledge Password Entropy & Breach Auditor
"""

__version__ = "1.0.0"
__author__ = "Shiraz"

from .auditor import audit_password
from .entropy import calculate_entropy
from .crack_simulator import simulate_crack_times
from .pwned_checker import check_pwned_hash
from .generator import generate_secure_password, generate_passphrase

__all__ = [
    "audit_password",
    "calculate_entropy",
    "simulate_crack_times",
    "check_pwned_hash",
    "generate_secure_password",
    "generate_passphrase"
]
