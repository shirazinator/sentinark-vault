"""
Sentinark-Vault: Zero-Knowledge k-Anonymity Breach Auditor
Queries the HaveIBeenPwned (HIBP) Pwned Passwords dataset securely.
Plaintext passwords NEVER leave the local machine.
"""

import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any


def check_pwned_hash(password: str, timeout_seconds: float = 3.5) -> Dict[str, Any]:
    """
    Checks if a password has appeared in known data breaches using k-Anonymity.
    
    Security Guarantee:
    1. SHA-1 hash is computed locally in memory.
    2. Only the first 5 characters (prefix) are sent to the API.
    3. The API returns candidate hash suffixes with breach counts.
    4. The comparison happens 100% locally on the user's computer.
    5. No plaintext password or full hash is ever transmitted across the network.
    """
    if not password:
        return {
            "pwned": False,
            "count": 0,
            "status": "empty",
            "message": "Empty password provided."
        }

    # 1. Compute local SHA-1
    sha1_full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_full[:5]
    suffix = sha1_full[5:]

    api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "Sentinark-Vault-Security-Auditor/1.0",
        "Add-Padding": "true"  # Requests random padding to resist response-size side-channel attacks
    }

    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            if response.status != 200:
                return {
                    "pwned": False,
                    "count": 0,
                    "status": "api_error",
                    "message": f"API responded with HTTP {response.status}."
                }
            
            raw_data = response.read().decode("utf-8")

        # Parse suffixes and counts
        # Each line: <SUFFIX>:<COUNT>
        for line in raw_data.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            item_suffix, count_str = line.split(":", 1)
            if item_suffix.upper() == suffix:
                count = int(count_str)
                return {
                    "pwned": True,
                    "count": count,
                    "status": "compromised",
                    "prefix": prefix,
                    "message": f"CRITICAL: Found in {count:,} known data breach records!"
                }

        return {
            "pwned": False,
            "count": 0,
            "status": "clean",
            "prefix": prefix,
            "message": "Zero records found in known breach databases."
        }

    except (urllib.error.URLError, TimeoutError) as e:
        return {
            "pwned": False,
            "count": 0,
            "status": "network_unavailable",
            "message": f"Breach verification skipped (Offline / Network timeout: {str(e)})."
        }
    except Exception as e:
        return {
            "pwned": False,
            "count": 0,
            "status": "error",
            "message": f"Lookup error: {str(e)}"
        }
