"""
Sentinark-Vault: Terminal CLI Interface
Run via: python3 -m sentinark_vault.cli
"""

import sys
import getpass
import argparse
from .auditor import audit_password
from .generator import generate_secure_password, generate_passphrase


# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"""{CYAN}{BOLD}
   ____             __  _                  __         _   __            ____ 
  / __/___ ___  __ / /_(_)__  ___ ________/ /__ _____| | / /__ ___ _____/ / /_
 _\ \/ -_) _ \/ // / __/ / _ \/ _ `/ __/ _  / _ `/ __/ |/ / _ `/ // / / _  __/
/___/\__/_//_/\_,_/\__/_/_//_/\_,_/_/  \_,_/\_,_/_/  |___/\_,_/\_,_/_/\_,_/\__/ 
     Zero-Knowledge Password Entropy, Breach & Hardware Crack Simulator
{RESET}""")


def main():
    parser = argparse.ArgumentParser(description="Sentinark-Vault: Cryptographic Password & Breach Auditor")
    parser.add_argument("--password", "-p", help="Password to audit (optional; if omitted, you will be prompted securely)")
    parser.add_argument("--no-breach-check", action="store_true", help="Skip online k-Anonymity breach lookup")
    parser.add_argument("--generate", "-g", action="store_true", help="Generate a high-entropy password without auditing")
    parser.add_argument("--passphrase", action="store_true", help="Generate a multi-word Diceware passphrase")
    
    args = parser.parse_args()
    print_banner()

    if args.generate or args.passphrase:
        if args.passphrase:
            pkg = generate_passphrase(num_words=5)
            print(f"{GREEN}{BOLD}Generated Diceware Passphrase:{RESET} {CYAN}{pkg['password']}{RESET}")
        else:
            pkg = generate_secure_password(length=18)
            print(f"{GREEN}{BOLD}Generated Alphanumeric Key:{RESET} {CYAN}{pkg['password']}{RESET}")
        print(f"\n{BOLD}Threat Model Breakdown:{RESET}")
        for k, v in pkg["threat_matrix"].items():
            print(f"  • {k.replace('_', ' ').title()}: {v}")
        return

    password = args.password
    if not password:
        try:
            password = getpass.getpass(f"{YELLOW}Enter password to securely audit (hidden from screen): {RESET}")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)

    if not password:
        print(f"{RED}Error: Empty password provided.{RESET}")
        sys.exit(1)

    print(f"\n{CYAN}[*] Running Zero-Knowledge cryptographic audit...{RESET}")
    report = audit_password(password, check_breaches=not args.no_breach_check)

    score = report["score"]
    score_color = GREEN if score >= 75 else (YELLOW if score >= 40 else RED)

    print(f"\n{BOLD}================ AUDIT DOSSIER ================{RESET}")
    print(f"Overall Defense Score: {score_color}{BOLD}{score} / 100{RESET}")
    print(f"Entropy:               {CYAN}{report['entropy']['entropy_bits']} bits{RESET} (Strength: {report['entropy']['strength_level']})")
    print(f"Keyspace:              {CYAN}{report['entropy']['keyspace_scientific']} possibilities{RESET}")
    print(f"Length:                {report['entropy']['length']} characters (Charset pool: {report['entropy']['charset_size']})")

    # Breach section
    breach = report["breach_audit"]
    if breach.get("pwned"):
        print(f"\n{RED}{BOLD}[!] DATA BREACH ALERT:{RESET} {RED}{breach['message']}{RESET}")
    else:
        print(f"\n{GREEN}[✓] Data Breach Status:{RESET} {GREEN}{breach['message']}{RESET}")

    # Vulnerabilities
    if report["patterns"]["vulnerabilities"]:
        print(f"\n{YELLOW}{BOLD}[!] Identified Vulnerabilities:{RESET}")
        for vuln in report["patterns"]["vulnerabilities"]:
            print(f"   - {vuln}")

    # Crack Times
    print(f"\n{BOLD}--- Simulated Hardware Crack Times (Zero-Lag O(1)) ---{RESET}")
    for key, hardware in report["crack_simulation"].items():
        time_str = hardware["time_human"]
        t_color = RED if "Instant" in time_str or "second" in time_str or "minute" in time_str else (YELLOW if "day" in time_str or "hour" in time_str else GREEN)
        print(f" • {hardware['name']:<45} : {t_color}{BOLD}{time_str}{RESET}")

    # Recommendations
    if report["recommendations"]:
        print(f"\n{BOLD}--- Actionable Security Recommendations ---{RESET}")
        for rec in report["recommendations"]:
            print(f" • {rec}")

    print(f"\n{BOLD}--- Suggested Cryptographic Replacement ---{RESET}")
    print(f"Complex Key:       {CYAN}{report['suggested_replacements']['complex']['password']}{RESET}")
    print(f"Diceware Phrase:   {CYAN}{report['suggested_replacements']['passphrase']['password']}{RESET}")
    print(f"{BOLD}================================================{RESET}\n")


if __name__ == "__main__":
    main()
