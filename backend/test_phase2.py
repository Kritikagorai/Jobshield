"""
test_phase2.py
--------------
Automated test suite for Phase 2: Core Analysis Engine & Rule-Based Services.
Validates all modules: privacy, validators, company registry, email domain,
red flags, pressure meter, similarity, salary check, complaint generator, and database.
"""

import sys
import unittest
from pathlib import Path

# Add backend directory to system path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from services.privacy import mask_aadhaar, mask_pan, mask_phone, mask_email, mask_sensitive_text
from services.validators import validate_cin, validate_gstin, validate_pan
from services.company_registry import find_company_in_registry, verify_company_credentials
from services.email_domain import is_free_email, has_suspicious_tld, detect_typosquatting, analyze_domain
from services.red_flags import scan_red_flags
from services.pressure_meter import calculate_pressure_score
from services.similarity import find_similar_scam_templates
from services.salary_check import evaluate_salary_benchmark
from services.complaint import generate_cybercrime_complaint
import database


class TestPhase2CoreServices(unittest.TestCase):

    def test_01_privacy_masking(self):
        """Tests that sensitive personal identifiers are properly masked."""
        raw_text = "Applicant Aadhaar: 1234 5678 9012, PAN: ABCDE1234F, Phone: +91 9876543210, Email: rahul.sharma@gmail.com"
        masked = mask_sensitive_text(raw_text)
        
        self.assertIn("XXXX-XXXX-9012", masked, "Aadhaar should be masked with last 4 digits visible")
        self.assertIn("XXXXX1234F", masked, "PAN should be masked with first 5 chars hidden")
        self.assertIn("******10", masked, "Phone should be masked in the middle")
        self.assertNotIn("rahul.sharma@gmail.com", masked, "Original email username should be masked")
        print(" [PASS] 01. Privacy Masker Verified")

    def test_02_validators_cin_gstin_pan(self):
        """Tests structural validation of Indian CIN, GSTIN, and PAN."""
        # Valid TCS CIN
        cin_res = validate_cin("L22210MH1995PLC084781")
        self.assertTrue(cin_res["valid"])
        self.assertTrue(cin_res["is_listed"])
        self.assertEqual(cin_res["state"], "MH")

        # Invalid CIN length
        invalid_cin = validate_cin("L22210MH1995PLC084")
        self.assertFalse(invalid_cin["valid"])

        # Valid TCS GSTIN
        gstin_res = validate_gstin("27AAACT2828Q1ZP")
        self.assertTrue(gstin_res["valid"])
        self.assertEqual(gstin_res["state_code"], "27")

        # Valid PAN
        pan_res = validate_pan("AAACT2828Q")
        self.assertTrue(pan_res["valid"])
        self.assertTrue(pan_res["is_corporate_pan"])
        print(" [PASS] 02. Validators (CIN, GSTIN, PAN) Verified")

    def test_03_company_registry_and_impersonation(self):
        """Tests company registry lookup and impersonation detection."""
        # Genuine TCS lookup
        comp = find_company_in_registry("Tata Consultancy Services")
        self.assertIsNotNone(comp)
        self.assertTrue(comp.get("is_genuine"))

        # Impersonation test: Scammer claims TCS but uses Gmail
        check = verify_company_credentials(
            claimed_name="Tata Consultancy Services",
            sender_email="hr.tcsrecruitment@gmail.com"
        )
        self.assertTrue(check["found_in_registry"])
        self.assertTrue(check["is_impersonation"])
        self.assertEqual(check["status"], "SUSPECTED_IMPERSONATION")
        print(" [PASS] 03. Company Registry & Impersonation Detection Verified")

    def test_04_email_and_domain_analysis(self):
        """Tests free email, suspicious TLDs, and typosquatting detection."""
        self.assertTrue(is_free_email("recruiter@gmail.com"))
        self.assertFalse(is_free_email("careers@tcs.com"))

        self.assertTrue(has_suspicious_tld("amazon-jobs.vip"))
        self.assertFalse(has_suspicious_tld("infosys.com"))

        typo = detect_typosquatting("tcs-hiring-portal.online")
        self.assertTrue(typo["is_typosquat"])
        self.assertEqual(typo["target_brand"], "TCS")
        print(" [PASS] 04. Domain & Typosquatting Analysis Verified")

    def test_05_red_flags_scanner(self):
        """Tests detection of payment demands, task scams, and legal threats."""
        scam_text = "Deposit refundable courier fee of Rs. 2,999 via Google Pay. Legal notice under Section 420 IPC will be dispatched if not paid."
        flags = scan_red_flags(scam_text)
        self.assertTrue(flags["has_red_flags"])
        self.assertTrue(flags["has_payment_demand"])
        self.assertGreater(flags["critical_count"], 0)
        
        categories = [f["category"] for f in flags["flags"]]
        self.assertIn("PAYMENT_DEMAND", categories)
        self.assertIn("LEGAL_INTIMIDATION", categories)
        print(" [PASS] 05. Red Flags Scanner Verified")

    def test_06_pressure_meter(self):
        """Tests psychological urgency and intimidation detection."""
        urgent_text = "Transfer Rs. 2,999 TODAY within 2 hours before 6 PM or your Naukri profile will be blacklisted across all IT companies!"
        pressure = calculate_pressure_score(urgent_text)
        self.assertGreaterEqual(pressure["pressure_score"], 50)
        self.assertIn(pressure["pressure_level"], ["High", "Extreme"])
        print(" [PASS] 06. Pressure Meter Verified")

    def test_07_similarity_matching(self):
        """Tests similarity matching against known scam templates."""
        sample_scam = "Brand new HP Core i7 Laptop dispatched. You must pay refundable courier insurance of Rs 2,999 to logistics coordinator via PhonePe."
        matches = find_similar_scam_templates(sample_scam, top_n=2)
        self.assertGreater(len(matches), 0)
        top_match = matches[0]
        self.assertGreater(top_match["similarity_pct"], 10.0)
        print(f" [PASS] 07. TF-IDF Similarity Verified (Top match: {top_match['title']} - {top_match['similarity_pct']}%)")

    def test_08_salary_benchmarking(self):
        """Tests detection of unrealistic salary anomalies."""
        # Unrealistic: fresher data entry paying 85,000/month
        eval_result = evaluate_salary_benchmark(
            role_name="Data Entry Operator",
            offered_salary_inr=85000,
            period="monthly"
        )
        self.assertTrue(eval_result["is_unrealistic"])
        self.assertEqual(eval_result["status"], "EXTREME_ANOMALY")

        # Realistic: fresher software engineer at 35,000/month (4.2 LPA)
        real_result = evaluate_salary_benchmark(
            role_name="Associate Software Engineer",
            offered_salary_inr=35000,
            period="monthly"
        )
        self.assertFalse(real_result["is_unrealistic"])
        self.assertEqual(real_result["status"], "REALISTIC_RANGE")
        print(" [PASS] 08. Salary Benchmarking Verified")

    def test_09_complaint_generator(self):
        """Tests official cybercrime complaint and bank freeze letter generation."""
        complaint = generate_cybercrime_complaint({
            "complainant_name": "Rohan Sharma",
            "complainant_phone": "+91 9876543210",
            "suspect_phone": "+91 9988776655",
            "suspect_upi": "fakehr@oksbi",
            "suspect_company": "Apex Global Placements",
            "amount_lost": 2999.0,
            "utr_number": "123456789012"
        })
        self.assertIn("cybercrime.gov.in", complaint["portal_complaint_text"])
        self.assertIn("123456789012", complaint["bank_freeze_letter"])
        self.assertTrue(any("Section 420" in s for s in complaint["applicable_legal_sections"]))
        print(" [PASS] 09. Legal Complaint & Bank Freeze Letter Verified")

    def test_10_database_and_fallback(self):
        """Tests database retrieval of companies, templates, benchmarks, and linked reports."""
        companies = database.db_manager.get_all_companies()
        templates = database.db_manager.get_scam_templates()
        benchmarks = database.db_manager.get_salary_benchmarks()
        reports = database.db_manager.get_reports()

        self.assertGreaterEqual(len(companies), 30)
        self.assertGreaterEqual(len(templates), 12)
        self.assertGreaterEqual(len(benchmarks), 20)
        self.assertGreaterEqual(len(reports), 25)

        # Test finding linked reports by phone
        linked = database.db_manager.find_linked_reports({"phone": "+919876543210"})
        self.assertGreater(len(linked), 0)
        print(f" [PASS] 10. Database Layer Verified ({database.db_manager.get_mode()}, {len(companies)} comps, {len(reports)} reports)")


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print(" [JobShield] RUNNING PHASE 2 TEST SUITE: Core Services & Database")
    print("=" * 65 + "\n")
    unittest.main()
