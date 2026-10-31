# 🛡️ Sentinark-Vault
### *Zero-Knowledge Password Entropy, Breach Vulnerability & Hardware Crack-Time Auditor*
**Part of the Sentinark Cybersecurity Suite**  
*Authored by Shiraz*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Security](https://img.shields.io/badge/Privacy-Zero--Knowledge-brightgreen)](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
[![Standard](https://img.shields.io/badge/Compliant-NIST%20SP%20800--63B-orange)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?logo=github)](https://shirazinator.github.io/sentinark-vault/)

> **🌐 Live Web Application (Zero-Installation):** [https://shirazinator.github.io/sentinark-vault/](https://shirazinator.github.io/sentinark-vault/)

---

## 📌 Overview

**Sentinark-Vault** is a privacy-first, zero-knowledge security tool designed to evaluate password strength, calculate information entropy, verify exposures against billions of compromised breach records, and mathematically simulate cracking times across state-of-the-art attack hardware (such as 8x NVIDIA RTX 4090 clusters and nation-state ASICs).

Unlike insecure online checkers, **Sentinark-Vault guarantees that plaintext passwords never leave your machine**.

```
+-------------------------------------------------------------------------+
|                           SENTINARK-VAULT                               |
|                  Zero-Knowledge Architectural Flow                      |
+-------------------------------------------------------------------------+
       |
       v
 [User Password]
       |
       +---> [Local SHA-1] ---> Prefix (5 chars) ---> [HIBP API Range Check]
       |                              |                      |
       |                              v                      v
       |                     [Remaining 35 chars] <==> [Candidate Hashes]
       |                              |
       |                              v (Zero Network Exposure)
       |                     [Breach Exposure Match]
       |
       +---> [Combinatorial Keyspace & Shannon Entropy Engine]
       |
       +---> [Closed-Form GPU Crack Simulator (O(1) - Zero CPU Lag)]
       |
       +---> [CSPRNG Generator & Threat-Model Risk Breakdown]
```

---

## ✨ Key Features

1. **Zero-Knowledge k-Anonymity Breach Verification:**
   - Evaluates whether a password exists in known data breaches without ever transmitting the password or its complete hash.
   - Computes a SHA-1 hash locally in memory, sends only the first 5 hexadecimal characters (`prefix`) to the HIBP dataset, and matches the suffix locally.

2. **Mathematical Crack-Time Simulation ($O(1)$ Complexity):**
   - **Guaranteed zero system lockup:** Simulates real-world brute-force resistance across hardware rigs using closed-form log-scale mathematics ($T = \frac{S/2}{\text{speed}}$) instead of dangerous CPU loops.
   - Benchmarks include:
     - Online Throttled Login Endpoints
     - Single Laptop CPU (MD5/NTLM)
     - Single NVIDIA RTX 4090 (20 GH/s)
     - 8x NVIDIA RTX 4090 Dedicated Cracking Rig (160 GH/s)
     - State-Sponsored ASIC Cluster (100 TH/s)

3. **Information & Shannon Entropy Analysis:**
   - Computes exact combinatorial keyspace ($S = R^L$) and information entropy in bits ($E = L \times \log_2 R$).
   - Evaluates Shannon entropy to detect repetitive or skewed character distributions.

4. **Pattern & Dictionary Vulnerability Detection:**
   - Flags keyboard walks (`qwerty`, `12345`), leetspeak substitutions (`p@ssw0rd`), calendar years (`19xx`, `20xx`), and dictionary roots.

5. **CSPRNG Password & Diceware Passphrase Generator:**
   - Uses Python's cryptographic `secrets` library (FIPS/NIST compliant).
   - Generates high-entropy passwords or multi-word Diceware passphrases.
   - Provides an educational **Threat Model Matrix** (explaining why a 100-character password is 0.00000001% vulnerable to brute force, but still 100% vulnerable to phishing fake login pages).

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/shirazinator/sentinark-vault.git
cd sentinark-vault
pip install -r requirements.txt
```

### 2. Launch Interactive Web Dashboard
Run the dark-mode cybersecurity console:
```bash
python3 -m sentinark_vault.web_app
```
Open your browser at: `http://127.0.0.1:5001`

### 3. CLI Terminal Audit
Audit securely with masked input (hidden from terminal):
```bash
python3 -m sentinark_vault.cli
```

Generate a cryptographically secure 18-character key:
```bash
python3 -m sentinark_vault.cli --generate
```

Generate a 5-word Diceware passphrase:
```bash
python3 -m sentinark_vault.cli --passphrase
```

---

## 🧪 Unit Testing

Run the test suite to verify cryptographic calculations and offline safety:
```bash
python3 -m unittest discover -s tests
```

---

## 🛡️ Threat Model & Security Disclosure

- **Plaintext Retention:** Sentinark-Vault never writes user passwords to disk, environment variables, or log files.
- **Side-Channel Mitigation:** When querying the breach API, the `Add-Padding: true` HTTP header is included to prevent packet-size inference attacks.
- **Phishing Defense:** Having an uncrackable password does not protect against credential-harvesting phishing sites. Always pair strong credentials with **FIDO2 / WebAuthn hardware security keys** or Time-based One-Time Passwords (TOTP).

---

## 📄 License
This project is licensed under the MIT License.
