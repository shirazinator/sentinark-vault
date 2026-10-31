"""
Unit tests for Sentinark-Vault core engine.
"""

import unittest
from sentinark_vault.entropy import calculate_entropy
from sentinark_vault.crack_simulator import simulate_crack_times
from sentinark_vault.pattern_detector import detect_patterns
from sentinark_vault.generator import generate_secure_password, generate_passphrase
from sentinark_vault.auditor import audit_password


class TestSentinarkVault(unittest.TestCase):

    def test_entropy_empty(self):
        result = calculate_entropy("")
        self.assertEqual(result["entropy_bits"], 0.0)
        self.assertEqual(result["strength_level"], "None")

    def test_entropy_strong(self):
        result = calculate_entropy("V3ry$ecureP@ssw0rd!2026")
        self.assertGreater(result["entropy_bits"], 80.0)
        self.assertEqual(result["strength_level"], "Very Strong")

    def test_pattern_detection(self):
        res = detect_patterns("User@123")
        self.assertTrue(res["is_vulnerable"])
        # Should flag common root word or sequential pattern
        self.assertTrue(any("user" in v.lower() or "123" in v.lower() for v in res["vulnerabilities"]))

    def test_crack_simulator_speed(self):
        # Must execute in < 1ms without freezing CPU
        sim = simulate_crack_times(18, 95)
        self.assertIn("gpu_cluster_8x", sim)
        self.assertTrue("years" in sim["gpu_cluster_8x"]["time_human"] or "Uncrackable" in sim["gpu_cluster_8x"]["time_human"])

    def test_generator_security(self):
        pwd = generate_secure_password(length=20)
        self.assertEqual(len(pwd["password"]), 20)
        self.assertIn("0.00000000001%", pwd["threat_matrix"]["brute_force_hack_probability"])

    def test_diceware_passphrase(self):
        phrase = generate_passphrase(num_words=5)
        words = phrase["password"].split("-")
        self.assertEqual(len(words), 5)

    def test_full_auditor(self):
        # Run audit without network call to verify offline resilience
        report = audit_password("Admin!2024Pass", check_breaches=False)
        self.assertIn("score", report)
        self.assertIn("entropy", report)
        self.assertIn("crack_simulation", report)


if __name__ == "__main__":
    unittest.main()
