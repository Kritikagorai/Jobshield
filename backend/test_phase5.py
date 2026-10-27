"""
Unit and Integration Test Suite for Phase 5 (Frontend Integration & Complete API Contract)
Validates all HTML page routes, static assets, and backend API endpoints consumed by the frontend.
"""
import unittest
from fastapi.testclient import TestClient

from main import app


class TestPhase5FrontendAndAPIs(unittest.TestCase):
    """Verifies that all frontend pages, assets, and APIs are operational and consistent."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_static_pages_served(self):
        """Checks that main frontend HTML pages are served correctly."""
        pages = [
            ("/", "JobShield"),
            ("/verify.html", "Deep Offer Letter"),
            ("/learn.html", "Job Scam Awareness"),
            ("/help.html", "Victim Emergency")
        ]
        for url, keyword in pages:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, f"Failed to load {url}")
            self.assertIn(keyword, response.text, f"Keyword '{keyword}' not found in {url}")

    def test_02_static_assets_served(self):
        """Checks that CSS and JavaScript files load with 200 OK."""
        assets = [
            "/css/style.css",
            "/js/app.js",
            "/js/i18n.js",
            "/js/charts.js"
        ]
        for asset in assets:
            response = self.client.get(asset)
            self.assertEqual(response.status_code, 200, f"Failed to load static asset {asset}")

    def test_03_stats_and_health_endpoints(self):
        """Checks platform statistics and health check endpoints."""
        res_health = self.client.get("/api/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json().get("status"), "ok")

        res_stats = self.client.get("/api/stats")
        self.assertEqual(res_stats.status_code, 200)
        data = res_stats.json()
        self.assertIn("total_reports", data)
        self.assertIn("registered_companies", data)
        self.assertGreaterEqual(data["total_reports"], 20)

    def test_04_analyze_endpoint_form_data(self):
        """Checks the main /analyze endpoint used by Home Scanner tab."""
        # 1. Genuine offer analysis
        res_genuine = self.client.post("/analyze", data={"text": "TCS Campus Recruitment Offer Letter. CTC: INR 3,85,000 per annum. Zero fee policy."})
        self.assertEqual(res_genuine.status_code, 200)
        data_gen = res_genuine.json()
        self.assertGreaterEqual(data_gen["trust_score"], 60)
        self.assertIn("reasons", data_gen)

        # 2. Urgent scam offer analysis
        res_scam = self.client.post("/analyze", data={"text": "Pay refundable laptop courier security fee INR 2999 immediately via Google Pay to hr.tcs@icici or police complaint will be filed."})
        self.assertEqual(res_scam.status_code, 200)
        data_scam = res_scam.json()
        self.assertLess(data_scam["trust_score"], 45)
        self.assertIn("High scam probability", data_scam["verdict"])

    def test_05_verify_letter_endpoint(self):
        """Checks the deep forensic offer letter verification endpoint."""
        letter_text = """
        TATA CONSULTANCY SERVICES LIMITED
        Corporate Identification Number (CIN): L22210MH1995PLC084781
        GSTIN: 27AAACT2876H1ZW
        Registered Office: TCS House, Raveline Street, Fort, Mumbai 400 001.
        Gross Annual Total Compensation (CTC): INR 3,85,000/- per annum.
        TCS adheres strictly to a zero-fee recruitment policy.
        """
        res = self.client.post("/api/verify-letter", data={"text": letter_text})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["trust_score"], 70)
        self.assertIn("forensic_checklist", data)
        self.assertGreaterEqual(len(data["forensic_checklist"]), 6)

    def test_06_samples_endpoint(self):
        """Checks that 1-click sample loaders return valid text."""
        for sample_key in ["genuine", "scam", "suspicious"]:
            res = self.client.get(f"/api/samples/{sample_key}")
            self.assertEqual(res.status_code, 200, f"Sample '{sample_key}' failed to load")
            data = res.json()
            self.assertIn("content", data)
            self.assertGreater(len(data["content"]), 50)

    def test_07_network_graph_and_syndicates(self):
        """Checks that network graph endpoints return vis-network formatted nodes and edges."""
        res_graph = self.client.get("/api/network/graph")
        self.assertEqual(res_graph.status_code, 200)
        g_data = res_graph.json()
        self.assertIn("nodes", g_data)
        self.assertIn("edges", g_data)
        self.assertGreater(len(g_data["nodes"]), 10)

        res_syn = self.client.get("/api/network/syndicates")
        self.assertEqual(res_syn.status_code, 200)
        syn_data = res_syn.json()
        self.assertIsInstance(syn_data, list)
        self.assertGreaterEqual(len(syn_data), 1)

    def test_08_reports_crud(self):
        """Checks community report submission and moderator status updates."""
        # Create a report
        new_report = {
            "company_name": "Test Scam Aviation Pvt Ltd",
            "phone": "+91 91234 56789",
            "email": "test@scamaviation.com",
            "upi_id": "aviationtest@icici",
            "amount_demanded": 3500.0,
            "scam_type": "Airport Ground Staff Medical Pass",
            "description": "Demanded gate pass fee via phone call.",
            "city": "Delhi"
        }
        res_post = self.client.post("/api/reports", json=new_report)
        self.assertEqual(res_post.status_code, 200)
        report_id = res_post.json().get("report_id")
        self.assertIsNotNone(report_id)

        # Update status
        res_patch = self.client.patch(f"/api/reports/{report_id}/status", json={"status": "approved"})
        self.assertEqual(res_patch.status_code, 200)
        self.assertEqual(res_patch.json().get("new_status"), "approved")

    def test_09_complaint_generator(self):
        """Checks automated complaint generator for cybercrime.gov.in and bank freeze."""
        payload = {
            "complainant_name": "Aman Verma",
            "complainant_phone": "+91 98765 00000",
            "complainant_city": "Noida, UP",
            "suspect_company": "Apex HR Logistics",
            "suspect_phone": "+91 91234 99999",
            "suspect_upi": "apexlogistics@icici",
            "amount_lost": 2999.0,
            "utr_number": "UTR202610219988",
            "incident_date": "2026-10-21",
            "narrative": "Sent money for laptop security deposit but recruiter stopped responding."
        }
        res = self.client.post("/api/generate-complaint", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("portal_draft", data)
        self.assertIn("bank_freeze_notice", data)
        self.assertIn("cybercrime.gov.in", data["portal_draft"])
        self.assertEqual(data["helpline_numbers"]["national_cyber_helpline"], "1930")
        self.assertIn("lien", data["bank_freeze_notice"].lower())


if __name__ == "__main__":
    unittest.main()
