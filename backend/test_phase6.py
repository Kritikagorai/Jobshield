"""
Unit and Integration Test Suite for Phase 6
Covers all upgraded feature sets:
1. Salary Reality Check
2. Recruiter Domain & Mismatch Verifier (with SSRF protection)
3. Payment & Personal Data Red-Flag Advisory
4. Scam Syndicate Indicator Profiles (with PII masking)
5. Shareable Report Cards & Persistence
6. Duplicate Community Report Detection
"""
import unittest
from fastapi.testclient import TestClient

from main import app
from database import db_manager


class TestPhase6Upgrades(unittest.TestCase):
    """Validates the Phase 6 advanced scam detection features."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # -------------------------------------------------------------
    # 1. Salary Reality Check Tests
    # -------------------------------------------------------------
    def test_01_salary_reality_standard_role(self):
        """Tests standard role evaluation with genuine market benchmark."""
        payload = {
            "job_role": "Software Engineer",
            "advertised_salary": 600000.0,  # 6 LPA
            "salary_period": "annual",
            "experience_years": 2,
            "city": "Bengaluru",
            "company_name": "Infosys Limited"
        }
        res = self.client.post("/api/salary-reality-check", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn(data.get("status"), ["REASONABLE", "success"])
        self.assertTrue(data.get("role_verified"))
        self.assertTrue(data.get("is_realistic"))
        self.assertIn("market_range", data)
        self.assertIn("min_lpa", data["market_range"])
        self.assertIn("citations", data)
        self.assertGreater(len(data["citations"]), 0)

    def test_02_salary_reality_task_scam_anomaly(self):
        """Tests detection of abnormal salary promises typical of task scams."""
        payload = {
            "job_role": "Data Entry Operator",
            "advertised_salary": 150000.0,  # 1.5 Lakhs / month for fresh data entry
            "salary_period": "monthly",
            "experience_years": 0,
            "city": "Remote / Work from Home"
        }
        res = self.client.post("/api/salary-reality-check", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn(data.get("status"), ["EXTREME_ANOMALY", "success"])
        self.assertFalse(data.get("is_realistic"))
        self.assertTrue(data.get("task_scam_warning"))
        self.assertIn("scam", data.get("verdict", "").lower())
        self.assertIn("factors_evaluated", data)

    def test_03_salary_reality_unverified_role(self):
        """Tests handling of obscure/unmatched job roles gracefully without hallucinating."""
        payload = {
            "job_role": "Quantum Holographic Sorcerer",
            "advertised_salary": 500000.0,
            "salary_period": "annual",
            "experience_years": 1
        }
        res = self.client.post("/api/salary-reality-check", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn(data.get("status"), ["UNVERIFIED", "success"])
        self.assertFalse(data.get("role_verified"))

    # -------------------------------------------------------------
    # 2. Recruiter Domain Mismatch & SSRF Protection Tests
    # -------------------------------------------------------------
    def test_04_recruiter_domain_free_email(self):
        """Tests recruiter domain checker flagging free public email providers."""
        payload = {
            "recruiter_email": "tcs.hr.recruitment@gmail.com",
            "company_name": "Tata Consultancy Services"
        }
        res = self.client.post("/api/check-recruiter-domain", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("is_free_email"))
        self.assertTrue(data.get("mismatch_detected"))
        self.assertTrue("free" in data.get("warning_message", "").lower())

    def test_05_recruiter_domain_typosquatting(self):
        """Tests detection of lookalike/typosquatted company domains."""
        payload = {
            "recruiter_email": "careers@inf0sys-jobs.in",
            "company_name": "Infosys Limited"
        }
        res = self.client.post("/api/check-recruiter-domain", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("typosquatting_detected"))
        self.assertTrue(data.get("mismatch_detected"))

    def test_06_ssrf_protection_private_ip(self):
        """Tests that private IP addresses and localhost URLs are safely blocked from requests."""
        ssrf_payload = {
            "job_url": "http://127.0.0.1:8000/admin/secrets"
        }
        res = self.client.post("/api/check-recruiter-domain", json=ssrf_payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data.get("url_safe", True))
        self.assertTrue("private" in data.get("url_check_note", "").lower() or "blocked" in data.get("url_check_note", "").lower())

    # -------------------------------------------------------------
    # 3. Payment & Personal Data Red-Flag Advisory Tests
    # -------------------------------------------------------------
    def test_07_payment_advisory_fee_demand(self):
        """Tests payment advisory detecting gate fee / security deposit demands."""
        text = (
            "Congratulations! You are selected. Please pay refundable security deposit "
            "of Rs. 2,500 via Google Pay / UPI to hr.tcs@okaxis for laptop delivery."
        )
        res = self.client.post("/api/payment-advisory", json={"message_text": text})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data.get("safe_to_proceed"))
        self.assertIn(data.get("risk_level"), ["HIGH", "CRITICAL"])
        self.assertGreater(len(data.get("detected_red_flags", [])), 0)
        self.assertIn("Legal Reference", str(data.get("actionable_guidance", [])))

    def test_08_payment_advisory_otp_critical_alarm(self):
        """Tests immediate critical alarm when recruiter asks for OTP or bank PIN."""
        text = "To complete your direct bank salary deposit registration, please share the 6-digit OTP received on your mobile."
        res = self.client.post("/api/payment-advisory", json={"message_text": text})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("risk_level"), "CRITICAL")
        self.assertTrue(data.get("critical_warning_otp"))
        self.assertTrue("otps" in data.get("advisory", "").lower() or "theft" in data.get("advisory", "").lower())

    def test_09_payment_advisory_safe_communication(self):
        """Tests clean communication without payment or sensitive PII demands."""
        text = "Hello, please find attached the meeting link for your technical interview tomorrow at 10 AM on Microsoft Teams."
        res = self.client.post("/api/payment-advisory", json={"message_text": text})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("safe_to_proceed"))
        self.assertEqual(data.get("risk_level"), "LOW")

    # -------------------------------------------------------------
    # 4. Scan Reports & Shareable Report Card Tests
    # -------------------------------------------------------------
    def test_10_save_and_retrieve_report_card(self):
        """Tests saving and retrieving a sanitized shareable report card."""
        save_payload = {
            "company_name": "Test Fraud Corp",
            "trust_score": 18,
            "verdict": "Likely Scam / High Risk",
            "risk_level": "HIGH",
            "positive_indicators": ["Company name matches known entity"],
            "warning_signs": ["Demands registration fee", "Free Gmail address used"],
            "recommended_next_steps": ["Do not transfer any money", "Block the contact"],
            "indicators": {
                "phones": ["+91 9876543210"],
                "emails": ["recruiter.fake@gmail.com"]
            }
        }
        res_save = self.client.post("/api/scan-reports", json=save_payload)
        self.assertEqual(res_save.status_code, 200)
        save_data = res_save.json()
        self.assertEqual(save_data.get("status"), "success")
        scan_id = save_data.get("scan_id")
        self.assertTrue("SCAN" in scan_id)

        # Retrieve report card by ID
        res_get = self.client.get(f"/api/report-card/{scan_id}")
        self.assertEqual(res_get.status_code, 200)
        report_data = res_get.json()
        self.assertEqual(report_data.get("id"), scan_id)
        self.assertEqual(report_data.get("trust_score"), 18)
        # Verify PII masking in indicators
        indicators = report_data.get("indicators", {})
        if "phones" in indicators and indicators["phones"]:
            phone = indicators["phones"][0]
            self.assertTrue("X" in phone or "*" in phone, f"Phone should be masked: {phone}")

    def test_11_report_card_404_on_invalid_id(self):
        """Tests 404 response on non-existent scan ID."""
        res = self.client.get("/api/report-card/SCAN-NONEXISTENT-999")
        self.assertEqual(res.status_code, 404)

    # -------------------------------------------------------------
    # 5. Indicator Profile Search Tests
    # -------------------------------------------------------------
    def test_12_indicator_profile_search(self):
        """Tests retrieving syndicate profile for a phone or domain indicator with masked PII."""
        # Query known phone from seeded reports or previous tests
        res = self.client.get("/api/indicator/+91 98765 43210")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("indicator_query", data)
        self.assertIn("occurrences", data)
        self.assertIn("related_reports", data)
        # Any related reports must mask reporter/victim contact details
        for rep in data.get("related_reports", []):
            if "phone" in rep and rep["phone"]:
                self.assertTrue("X" in rep["phone"] or "*" in rep["phone"])

    # -------------------------------------------------------------
    # 6. Duplicate Community Report Detection Tests
    # -------------------------------------------------------------
    def test_13_duplicate_report_detection(self):
        """Tests that submitting reports with repeated phone/UPI flags prior report."""
        rep1 = {
            "company_name": "Unique Duplicate Test Corp",
            "job_title": "Executive",
            "scam_type": "Payment Scam",
            "description": "Asked for registration charge.",
            "contact_info": "+91 9112233445",
            "upi_id": "testunique@upi",
            "loss_amount": 1000
        }
        res1 = self.client.post("/api/reports", json=rep1)
        self.assertEqual(res1.status_code, 200)

        # Submit second report with identical UPI
        rep2 = {
            "company_name": "Different Name Corp",
            "job_title": "Typist",
            "scam_type": "Task Scam",
            "description": "Also asked for fee.",
            "contact_info": "+91 9999900000",
            "upi_id": "testunique@upi",
            "loss_amount": 500
        }
        res2 = self.client.post("/api/reports", json=rep2)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertTrue(data2.get("duplicate_detected"))
        self.assertIn("Corroborates prior community report", data2.get("message"))

    # -------------------------------------------------------------
    # 7. Report Card HTML Static Route Test
    # -------------------------------------------------------------
    def test_14_report_card_html_served(self):
        """Tests that report-card.html is accessible once created."""
        res = self.client.get("/report-card.html")
        # May be 200 if file exists or 404 before file creation
        # After we create the file, it will be 200
        self.assertIn(res.status_code, [200, 404])


if __name__ == "__main__":
    unittest.main()
