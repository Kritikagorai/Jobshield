"""
JobShield – Fake Job Detector Backend.
Tagline: "Scam hone se pehle pakdo"
Provides REST API endpoints for all phases:
- Phase 1 & 2: Quick rule-based & Scikit-learn ML fraud detector (/analyze)
- Phase 3: Forensic offer letter verifier & salary reality checker (/api/verify-letter)
- Phase 5: Community reporting & moderation CRUD (/api/reports)
- Phase 6: Awareness education & quiz assistance
- Phase 7: National Cyber Crime Portal & Bank freeze complaint generator (/api/generate-complaint)
"""
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Form, UploadFile, File, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from config import FRONTEND_DIR, HOST, PORT, BACKEND_DIR
from database import db_manager
from services.entity_extractor import (
    extract_all_entities,
    extract_text_from_file_bytes,
    FREE_EMAIL_DOMAINS
)
from services.email_domain import (
    is_free_email,
    verify_recruiter_domain_mismatch,
    is_safe_url
)
from services.salary_check import evaluate_salary_reality_check
from services.payment_advisor import evaluate_payment_safety
from services.privacy import mask_sensitive_text
from services.ml_classifier import MLScamClassifier
from services.forensic_verifier import verify_offer_letter
from services.complaint import generate_cybercrime_complaint
from services.graph_service import build_network_graph, get_syndicate_clusters

# Initialize FastAPI application
app = FastAPI(
    title="JobShield API",
    description="Backend API for JobShield – Fake Job Detector ('Scam hone se pehle pakdo')",
    version="2.0.0"
)

# Enable CORS for cross-origin local requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ML Classifier with database scam templates
ml_classifier = MLScamClassifier(db_manager.get_scam_templates())


# Pydantic Request Models
class AnalyzeRequest(BaseModel):
    text: Optional[str] = ""
    url: Optional[str] = ""
    email: Optional[str] = ""
    phone: Optional[str] = ""


class SalaryRealityRequest(BaseModel):
    role: Optional[str] = ""
    job_role: Optional[str] = ""
    company_name: Optional[str] = ""
    location: Optional[str] = ""
    city: Optional[str] = ""
    experience_level: Optional[str] = ""
    experience_years: Optional[Any] = None
    advertised_salary: Optional[Any] = 0
    period: Optional[str] = ""
    salary_period: Optional[str] = ""
    employment_type: Optional[str] = "full-time"

    @property
    def resolved_role(self) -> str:
        return self.role or self.job_role or ""

    @property
    def resolved_location(self) -> str:
        return self.location or self.city or ""

    @property
    def resolved_experience(self) -> str:
        if self.experience_years is not None:
            return str(self.experience_years)
        return self.experience_level or "fresher"

    @property
    def resolved_period(self) -> str:
        return self.period or self.salary_period or "monthly"


class DomainCheckRequest(BaseModel):
    email_or_domain: Optional[str] = ""
    recruiter_email: Optional[str] = ""
    company_name: Optional[str] = ""
    url: Optional[str] = ""
    job_url: Optional[str] = ""

    @property
    def resolved_email_or_domain(self) -> str:
        return self.email_or_domain or self.recruiter_email or ""

    @property
    def resolved_url(self) -> str:
        return self.url or self.job_url or ""


class PaymentAdvisorRequest(BaseModel):
    text: Optional[str] = ""
    message_text: Optional[str] = ""

    @property
    def resolved_text(self) -> str:
        return self.text or self.message_text or ""


class ScanReportSaveRequest(BaseModel):
    id: Optional[str] = ""
    trust_score: Optional[int] = 50
    verdict: Optional[str] = "Needs verification"
    risk_category: Optional[str] = "Needs verification"
    risk_level: Optional[str] = ""
    confidence: Optional[str] = "Moderate"
    company_name: Optional[str] = ""
    summary: Optional[str] = ""
    positive_indicators: Optional[List[str]] = []
    warning_signs: Optional[List[str]] = []
    recommended_steps: Optional[List[str]] = []
    recommended_next_steps: Optional[List[str]] = []
    findings: Optional[List[Dict[str, Any]]] = []
    evidence: Optional[Dict[str, Any]] = {}
    indicators: Optional[Dict[str, Any]] = {}
    limitations_text: Optional[str] = ""


class ReportSubmission(BaseModel):
    company_name: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    upi_id: Optional[str] = ""
    domain: Optional[str] = ""
    telegram: Optional[str] = ""
    amount_demanded: Optional[float] = 0.0
    scam_type: Optional[str] = "Job Offer Fraud"
    description: Optional[str] = ""
    city: Optional[str] = "Pan-India"


class StatusUpdate(BaseModel):
    status: str  # 'approved', 'rejected', 'pending'


class ComplaintRequest(BaseModel):
    complainant_name: Optional[str] = ""
    complainant_phone: Optional[str] = ""
    complainant_city: Optional[str] = "India"
    suspect_name: Optional[str] = ""
    suspect_phone: Optional[str] = ""
    suspect_email: Optional[str] = ""
    suspect_upi: Optional[str] = ""
    suspect_company: Optional[str] = ""
    amount_lost: Optional[float] = 0.0
    utr_number: Optional[str] = ""
    incident_date: Optional[str] = ""
    scam_category: Optional[str] = "Employment / Job Offer Fraud"
    narrative: Optional[str] = ""


# -------------------------------------------------------------
# System & Health Endpoints
# -------------------------------------------------------------
@app.get("/health")
@app.get("/api/health")
def health_check():
    """Returns server health, database mode, and high-level platform stats."""
    stats = db_manager.get_stats()
    return {
        "status": "ok",
        "app_name": "JobShield – Fake Job Detector",
        "tagline": "Scam hone se pehle pakdo",
        "database_mode": db_manager.get_mode(),
        "stats": stats
    }


@app.get("/api/stats")
def get_stats():
    """Returns live metrics for dashboard banners."""
    return db_manager.get_stats()


# -------------------------------------------------------------
# Phase 1 & 2: Instant Job Scam Scanner (/analyze)
# -------------------------------------------------------------
@app.post("/analyze")
@app.post("/api/analyze")
async def analyze_job(
    request: Request,
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    company_name: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    """
    Analyzes job description text, URL, recruiter email, phone, or uploaded document.
    Combines rule-based checks, entity extraction, Scikit-learn TF-IDF similarity,
    and database syndicate matching.
    """
    input_text = text or ""
    input_url = url or ""
    input_email = email or ""
    input_phone = phone or ""
    input_company = company_name or ""

    # If request sent as JSON body
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            input_text = body.get("text", "") or input_text
            input_url = body.get("url", "") or input_url
            input_email = body.get("email", "") or input_email
            input_phone = body.get("phone", "") or input_phone
            input_company = body.get("company_name", "") or input_company
        except Exception:
            pass

    # Extract text from file if uploaded
    file_warning = None
    if file:
        MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
        ALLOWED_EXTS = {".txt", ".pdf", ".docx", ".doc", ".png", ".jpg", ".jpeg", ".webp", ".bmp"}
        ext = Path(file.filename).suffix.lower()
        if ext and ext not in ALLOWED_EXTS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format '{ext}'. Allowed formats: TXT, PDF, DOCX, PNG, JPG, WEBP."
            )
        try:
            file_bytes = await file.read()
            if len(file_bytes) > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=400,
                    detail="File exceeds maximum allowed size of 10 MB."
                )
            from services.text_extractor import extract_document_text
            extracted_res = extract_document_text(file.filename, file_bytes)
            if extracted_res.get("text"):
                input_text = (input_text + "\n" + extracted_res["text"]).strip()
            if extracted_res.get("warning"):
                file_warning = extracted_res["warning"]
        except HTTPException:
            raise
        except Exception as e:
            input_text += f"\n[File reading error: {str(e)}]"

    if not any([input_text.strip(), input_url.strip(), input_email.strip(), input_phone.strip()]):
        raise HTTPException(
            status_code=400,
            detail="Please provide at least one input: job description text, URL, recruiter email, phone number, or document."
        )

    # 1. Entity Extraction
    combined_content = f"{input_text}\n{input_url}\n{input_email}\n{input_phone}"
    # Pass explicit company hint (user-supplied) so extraction doesn't mis-identify
    entities = extract_all_entities(combined_content, explicit_company=input_company or None)

    # Add explicit inputs to entities
    if input_email and not any(e["email"] == input_email.lower() for e in entities.get("emails", [])):
        domain = input_email.split("@")[-1].lower() if "@" in input_email else ""
        entities.setdefault("emails", []).append({
            "email": input_email.lower(),
            "domain": domain,
            "is_free_provider": is_free_email(domain),
            "is_known_corp": False
        })
    if input_phone and input_phone not in entities.get("phones", []):
        entities.setdefault("phones", []).append(input_phone)

    # 2. Comprehensive Explainable Trust Scoring
    from services.scoring import calculate_comprehensive_trust_score
    scoring_result = calculate_comprehensive_trust_score(
        text=input_text,
        url=input_url,
        email=input_email,
        phone=input_phone,
        extracted_entities=entities
    )

    # If there was a file extraction warning (e.g. OCR missing), notify candidate
    if file_warning:
        scoring_result["reasons"].append({
            "severity": "medium",
            "icon": "file-text",
            "title": "Document Notice",
            "description": file_warning
        })

    # Auto-generate and save a sanitized report card for 1-click sharing
    import uuid
    from datetime import datetime, timezone
    scan_id = f"JS-SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    phone_clean = "".join(ch for ch in input_phone if ch.isdigit())
    masked_phone_str = f"+91 {phone_clean[-10:-8]}******{phone_clean[-2:]}" if len(phone_clean) >= 10 else input_phone

    sanitized_evidence = {
        "text_sample": mask_sensitive_text(input_text[:350]) if input_text else "",
        "url": input_url,
        "email": input_email.split("@")[0][:2] + "***@" + input_email.split("@")[1] if "@" in input_email else "",
        "phone": masked_phone_str,
        "extracted_entities": {
            "company_name": entities.get("company_name") or (input_company.strip() if input_company else None),
            "cin": entities.get("cin"),
            "upi_ids": entities.get("upi_ids", []),
            "salaries": [s.get("raw_text") for s in entities.get("salaries", [])]
        }
    }

    db_manager.save_scan_result({
        "id": scan_id,
        "report_type": "Multimodal Fraud Scan",
        "summary": f"Job Authenticity Assessment: {scoring_result.get('verdict')}",
        "trust_score": scoring_result["trust_score"],
        "risk_level": scoring_result.get("risk_category", "Needs verification"),
        "confidence": scoring_result.get("confidence", "Moderate"),
        "findings": scoring_result.get("reasons", []),
        "evidence": sanitized_evidence,
        "recommended_steps": scoring_result.get("recommended_next_steps", []),
        "limitations_text": scoring_result.get("disclaimer", "")
    })

    return {
        "scan_id": scan_id,
        "shareable_url": f"/report-card.html?id={scan_id}",
        "trust_score": scoring_result["trust_score"],
        "score_direction": scoring_result.get("score_direction", "Higher is safer (0 = High Scam Risk, 100 = Likely Genuine)"),
        "verdict": scoring_result["verdict"],
        "risk_category": scoring_result.get("risk_category", "Needs verification"),
        "confidence": scoring_result["confidence"],
        "red_banner_warning": scoring_result.get("red_banner_warning"),
        "reasons": scoring_result["reasons"],
        "positive_indicators": scoring_result.get("positive_indicators", []),
        "warning_signs": scoring_result.get("warning_signs", []),
        "recommended_next_steps": scoring_result.get("recommended_next_steps", []),
        "ml_match": scoring_result.get("ml_analysis"),
        "pressure_analysis": scoring_result.get("pressure_analysis"),
        "company_verification": scoring_result.get("company_verification"),
        "extracted_entities": {
            "company_name": entities.get("company_name") or (input_company.strip() if input_company else None),
            "cin": entities.get("cin"),
            "phones": entities.get("phones"),
            "emails": [e["email"] for e in entities.get("emails", [])],
            "upi_ids": entities.get("upi_ids"),
            "salaries": [s.get("raw_text") for s in entities.get("salaries", [])]
        },
        "linked_reports_count": scoring_result.get("linked_reports_count", 0),
        "disclaimer": scoring_result.get("disclaimer")
    }


# -------------------------------------------------------------
# New Feature 2: Salary Reality Check (/api/salary-reality-check)
# -------------------------------------------------------------
@app.post("/api/salary-reality-check")
def salary_reality_check_endpoint(data: SalaryRealityRequest):
    """
    Evaluates whether an advertised salary is realistic for the specified role,
    location, experience level, and employment type.
    """
    return evaluate_salary_reality_check(
        role=data.resolved_role,
        company_name=data.company_name or "",
        location=data.resolved_location,
        experience_level=data.resolved_experience,
        advertised_salary=data.advertised_salary,
        period=data.resolved_period,
        employment_type=data.employment_type or "full-time"
    )


# -------------------------------------------------------------
# New Feature 4: Recruiter Email & Domain Mismatch Checker (/api/check-recruiter-domain)
# -------------------------------------------------------------
@app.post("/api/check-recruiter-domain")
def check_recruiter_domain_endpoint(data: DomainCheckRequest):
    """
    Checks recruiter email domain against official company registry,
    detects typosquatting, free emails, lookalike subdomains, and URL safety.
    """
    return verify_recruiter_domain_mismatch(
        email_or_domain=data.resolved_email_or_domain,
        claimed_company=data.company_name or "",
        url=data.resolved_url
    )


# -------------------------------------------------------------
# New Feature 5: Payment & Personal Data Red-Flag Detector (/api/payment-advisory)
# -------------------------------------------------------------
@app.post("/api/payment-advisory")
def payment_advisory_endpoint(data: PaymentAdvisorRequest):
    """
    Evaluates whether a job request involves unsafe payments or identity data sharing.
    Answers: 'Should I pay or share this information for this job?'
    """
    return evaluate_payment_safety(data.resolved_text)


# -------------------------------------------------------------
# New Feature 6: Searchable Indicator Profile (/api/indicator/{indicator_value})
# -------------------------------------------------------------
@app.get("/api/indicator/{indicator_value}")
def get_indicator_profile_endpoint(indicator_value: str):
    """
    Retrieves the connected community telemetry profile for an indicator
    (phone, UPI handle, domain, or company) with masked PII.
    """
    return db_manager.get_indicator_profile(indicator_value)


# -------------------------------------------------------------
# New Feature 7: Shareable Report Cards (/api/scan-reports)
# -------------------------------------------------------------
@app.post("/api/scan-reports")
def save_scan_report_endpoint(data: ScanReportSaveRequest):
    """
    Generates and persists a shareable, sanitized scan report card with an unpredictable ID.
    """
    payload = data.model_dump()
    if not payload.get("recommended_steps") and payload.get("recommended_next_steps"):
        payload["recommended_steps"] = payload["recommended_next_steps"]
    if not payload.get("risk_category") and payload.get("risk_level"):
        payload["risk_category"] = payload["risk_level"]
    scan_id = db_manager.save_scan_result(payload)
    return {
        "status": "success",
        "scan_id": scan_id,
        "shareable_url": f"/report-card.html?id={scan_id}",
        "message": "Report card created successfully."
    }


@app.get("/api/report-card/{scan_id}")
def get_report_card_endpoint(scan_id: str):
    """
    Retrieves a sanitized report card by its reference ID.
    """
    report = db_manager.get_scan_result(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report card not found or expired.")
    return report


# -------------------------------------------------------------
# Phase 3: Forensic Offer Letter Verifier (/api/verify-letter)
# -------------------------------------------------------------
@app.post("/api/verify-letter")
async def verify_letter_endpoint(
    request: Request,
    text: Optional[str] = Form(None),
    company_name: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    """
    Forensic Offer Letter verification endpoint.
    Accepts text or uploaded offer letter (PDF, TXT, DOCX, Image), with optional explicit company name.
    Performs full 6-pillar analysis against MCA registry and Indian salary benchmarks.
    """
    content = text or ""
    filename = "Pasted Text"
    comp_input = company_name

    if "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.json()
            content = body.get("text", "") or content
            comp_input = body.get("company_name", "") or comp_input
        except Exception:
            pass

    if file:
        filename = file.filename
        file_bytes = await file.read()
        extracted = extract_text_from_file_bytes(filename, file_bytes)
        content = (content + "\n" + extracted).strip()

    if not content.strip():
        raise HTTPException(
            status_code=400,
            detail="Please paste offer letter text or upload a document file (TXT, PDF, DOCX, or Image)."
        )

    result = verify_offer_letter(content, db_manager, filename=filename, company_name=comp_input)
    return result




# -------------------------------------------------------------
# Phase 5: Community Reporting & Moderation (/api/reports)
# -------------------------------------------------------------
@app.get("/api/reports")
def get_reports_endpoint(
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: Optional[int] = Query(100)
):
    """Retrieves reports from database with search and status filtering."""
    return db_manager.get_reports(status=status, limit=limit, search=search)


@app.post("/api/reports")
def submit_report(report: ReportSubmission):
    """Submits a new community scam report into the database with duplicate detection."""
    rep_dict = report.model_dump()
    existing = db_manager.check_duplicate_report(rep_dict)
    rid = db_manager.insert_report(rep_dict)
    response_payload = {
        "status": "success",
        "report_id": rid,
        "message": f"Scam report {rid} logged successfully."
    }
    if existing:
        response_payload["duplicate_detected"] = True
        response_payload["prior_report_id"] = existing.get("id")
        response_payload["message"] = f"Report {rid} recorded. Corroborates prior community report {existing.get('id')}."
    return response_payload


@app.patch("/api/reports/{report_id}/status")
def update_report_status_endpoint(report_id: str, update: StatusUpdate):
    """Updates moderation status ('approved', 'rejected', 'pending')."""
    success = db_manager.update_report_status(report_id, update.status)
    if not success:
        raise HTTPException(status_code=404, detail="Report ID not found.")
    return {"status": "success", "report_id": report_id, "new_status": update.status}


@app.delete("/api/reports/{report_id}")
def delete_report_endpoint(report_id: str):
    """Deletes a report by ID."""
    success = db_manager.delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="Report ID not found.")
    return {"status": "success", "deleted_id": report_id}


# -------------------------------------------------------------
# Phase 2 & 3: Master Data Lookups (Companies & Salaries)
# -------------------------------------------------------------
@app.get("/api/companies")
def get_companies(query: Optional[str] = None):
    """Returns official registered company profiles or searches by keyword."""
    if query:
        comp = db_manager.find_company(query)
        return [comp] if comp else []
    return db_manager.get_all_companies()


@app.get("/api/salary-benchmarks")
def get_salaries(role: Optional[str] = None):
    """Returns official Indian market salary benchmarks."""
    return db_manager.get_salary_benchmarks(role=role)


# -------------------------------------------------------------
# Syndicate Network Analysis Endpoints (/api/network/graph, /api/network/syndicates)
# -------------------------------------------------------------
@app.get("/api/network/graph")
def get_network_graph():
    """Returns vis-network formatted nodes and edges for syndicate analysis."""
    reports = db_manager.get_reports()
    return build_network_graph(reports)


@app.get("/api/network/syndicates")
def get_syndicates():
    """Returns connected syndicate clusters identified across community reports."""
    reports = db_manager.get_reports()
    return get_syndicate_clusters(reports)


# -------------------------------------------------------------
# Phase 7: Emergency Complaint Generator (/api/generate-complaint)
# -------------------------------------------------------------
@app.post("/api/generate-complaint")
def generate_complaint_endpoint(data: ComplaintRequest):
    """Generates official cybercrime.gov.in draft and bank freeze notice."""
    return generate_cybercrime_complaint(data.model_dump())



# -------------------------------------------------------------
# Phase 6: Awareness Education Endpoints (/api/quiz, /api/tips, /api/awareness)
# -------------------------------------------------------------

QUIZ_QUESTIONS_DATA = [
    {
        "id": 1,
        "question": "1. A recruiter from 'TCS Recruitment Hub' sends an offer on WhatsApp offering 8.5 LPA without any technical interview, asking for Rs 2,999 refundable laptop courier insurance via Google Pay. What should you do?",
        "options": [
            {"id": "a", "text": "Pay immediately since it is refundable and TCS is a reputable company.", "correct": False},
            {"id": "b", "text": "Never pay. TCS has a strict zero-fee policy; legitimate employers never charge for equipment or courier insurance.", "correct": True},
            {"id": "c", "text": "Negotiate the courier insurance fee to Rs 1,000.", "correct": False}
        ],
        "explanation": "Rule #1 of Indian Corporate Hiring: Legitimate companies bear 100% of equipment and recruitment costs. Demanding any fee via UPI is 100% fraud.",
        "category": "Fee Fraud",
        "difficulty": "easy"
    },
    {
        "id": 2,
        "question": "2. You receive an email from 'recruiter.infosys.careers@gmail.com' confirming your selection. What is the biggest red flag here?",
        "options": [
            {"id": "a", "text": "They used Gmail instead of the official @infosys.com corporate domain.", "correct": True},
            {"id": "b", "text": "The font of the email is Arial.", "correct": False},
            {"id": "c", "text": "The email was sent on a Saturday.", "correct": False}
        ],
        "explanation": "Major corporations like Infosys, TCS, and Wipro strictly prohibit HR personnel from communicating with applicants using free public emails like Gmail or Yahoo.",
        "category": "Email Domain Fraud",
        "difficulty": "easy"
    },
    {
        "id": 3,
        "question": "3. A recruiter threatens that if you don't send Rs 4,999 within 2 hours, they will file an FIR under IPC Section 420 and blacklist you across all Indian IT portals. How should you respond?",
        "options": [
            {"id": "a", "text": "Panic and send the money to protect your Naukri profile.", "correct": False},
            {"id": "b", "text": "Ignore the threat and block the number. It is an extortion trap; candidates cannot be arrested or blacklisted for declining an offer.", "correct": True},
            {"id": "c", "text": "Apologize and ask for a 24-hour extension.", "correct": False}
        ],
        "explanation": "Employment fraud syndicates use fake legal threats (invoking IPC 420 or portal blacklisting) to induce psychological panic. No such authority exists.",
        "category": "Extortion & Threats",
        "difficulty": "medium"
    },
    {
        "id": 4,
        "question": "4. You are offered a part-time job earning Rs 3,000 daily by simply liking YouTube videos and rating Google hotels on Telegram. What type of scam is this?",
        "options": [
            {"id": "a", "text": "Genuine digital marketing freelance gig.", "correct": False},
            {"id": "b", "text": "Task Earning & Prepaid Recharge Scam.", "correct": True},
            {"id": "c", "text": "Affiliate referral program.", "correct": False}
        ],
        "explanation": "Task Earning scams pay tiny sums (Rs 150) initially to gain trust, then trick victims into depositing thousands in 'VIP task recharges' before freezing all withdrawals.",
        "category": "Task Earning Scam",
        "difficulty": "medium"
    },
    {
        "id": 5,
        "question": "5. A company offering a 'Work-from-Home Offline Data Entry' job demands Rs 1,850 for a 'Digital Agreement Stamp Duty & Software Login Key'. Is this standard practice?",
        "options": [
            {"id": "a", "text": "Yes, stamp duty is legally mandatory for all remote agreements.", "correct": False},
            {"id": "b", "text": "No, this is a classic typing scam designed to steal fee money and extort victims later.", "correct": True},
            {"id": "c", "text": "Only if the company provides a GST invoice.", "correct": False}
        ],
        "explanation": "Data entry/typing scams lure freshers with promises of Rs 30,000/month, demand agreement fees, and then invent errors in work to demand Rs 10,000+ cancellation fees.",
        "category": "Data Entry Scam",
        "difficulty": "medium"
    },
    {
        "id": 6,
        "question": "6. An offer letter mentions Corporate Identification Number (CIN) 'L22210MH1995PLC084781'. What does the letter 'L' at the start signify?",
        "options": [
            {"id": "a", "text": "Limited Liability Partnership (LLP)", "correct": False},
            {"id": "b", "text": "Listed Company on Indian Stock Exchanges (BSE/NSE)", "correct": True},
            {"id": "c", "text": "Local State Government Enterprise", "correct": False}
        ],
        "explanation": "In an MCA CIN, 'L' signifies a publicly Listed company (e.g. TCS), while 'U' signifies an Unlisted company.",
        "category": "Document Verification",
        "difficulty": "hard"
    },
    {
        "id": 7,
        "question": "7. You applied for an Airport Ground Staff position. The agency demands Rs 2,500 for an 'Airport Security Gate Pass & Medical Uniform Measurement'. Genuine or scam?",
        "options": [
            {"id": "a", "text": "Genuine, because airports have high security protocols.", "correct": False},
            {"id": "b", "text": "Scam. Airport authorities and airlines (IndiGo, Air India) issue security passes directly without cash fees.", "correct": True},
            {"id": "c", "text": "Genuine if paid via Paytm.", "correct": False}
        ],
        "explanation": "Aviation ground staff scams are rampant in India. Airport entry passes (BCAS AEPs) are sponsored directly by airlines and airports at zero charge to candidates.",
        "category": "Airport Staff Scam",
        "difficulty": "medium"
    },
    {
        "id": 8,
        "question": "8. A recruiter asks you to share your netbanking user ID and password to 'verify your salary credit account'. What should you do?",
        "options": [
            {"id": "a", "text": "Share only the password, not the OTP.", "correct": False},
            {"id": "b", "text": "Never share banking passwords, OTPs, or debit card PINs under any circumstances.", "correct": True},
            {"id": "c", "text": "Create a new bank account with Rs 500 balance and share credentials.", "correct": False}
        ],
        "explanation": "Employers only need your Account Number and IFSC Code for salary deposits. Anyone asking for passwords or OTPs is attempting bank account takeover.",
        "category": "Banking Fraud",
        "difficulty": "easy"
    },
    {
        "id": 9,
        "question": "9. What is the National Cyber Crime Helpline number in India to report job frauds and freeze unauthorized UPI transactions?",
        "options": [
            {"id": "a", "text": "100", "correct": False},
            {"id": "b", "text": "1930", "correct": True},
            {"id": "c", "text": "1098", "correct": False}
        ],
        "explanation": "1930 is India's dedicated Citizen Financial Cyber Fraud Reporting System helpline operated by the Ministry of Home Affairs (MHA).",
        "category": "Emergency Response",
        "difficulty": "easy"
    },
    {
        "id": 10,
        "question": "10. What is the 'Golden Hour' in cyber fraud reporting?",
        "options": [
            {"id": "a", "text": "The first 2 hours immediately after money is transferred, when banks can freeze the suspect account before withdrawal.", "correct": True},
            {"id": "b", "text": "The 24-hour window before joining a job.", "correct": False},
            {"id": "c", "text": "The time of day when cybercrime portals open.", "correct": False}
        ],
        "explanation": "Reporting to 1930 within the Golden Hour allows police and banks to place an immediate lien on the fraudster's UPI/bank account before funds are laundered.",
        "category": "Emergency Response",
        "difficulty": "hard"
    }
]

SAFETY_TIPS_DATA = [
    {
        "id": 1,
        "category": "Email Verification",
        "icon": "📧",
        "tip": "Always verify recruiter email domains",
        "detail": "Legitimate companies like TCS, Infosys, Wipro use official domains (e.g. @tcs.com, @infosys.com). Any job offer from @gmail.com, @yahoo.com, or @outlook.com is a major red flag.",
        "severity": "critical"
    },
    {
        "id": 2,
        "category": "Zero Fee Policy",
        "icon": "💰",
        "tip": "Never pay any upfront fee for a job",
        "detail": "All reputable Indian companies (MNCs and PSUs) follow a strict zero-fee recruitment policy. Registration fees, laptop deposits, uniform charges, gate pass fees, and training costs are 100% scam indicators.",
        "severity": "critical"
    },
    {
        "id": 3,
        "category": "Document Checks",
        "icon": "📄",
        "tip": "Verify offer letter CIN on MCA portal",
        "detail": "Every legitimate Indian company has a 21-character CIN (Corporate Identification Number). Verify it free at: https://www.mca.gov.in/. Fake companies either omit this or use invalid CINs.",
        "severity": "high"
    },
    {
        "id": 4,
        "category": "Interview Process",
        "icon": "🎯",
        "tip": "Demand a proper multi-stage interview",
        "detail": "Instant selection via WhatsApp, Telegram, or a single 5-minute video call without any technical assessment is a hallmark of fake job offers. Real hiring involves multiple rounds.",
        "severity": "high"
    },
    {
        "id": 5,
        "category": "Salary Reality",
        "icon": "📊",
        "tip": "Cross-check offered salary against market standards",
        "detail": "Fresher salary in India: IT (3.5-7.5 LPA), Banking (2.5-4 LPA), Data Entry (1.2-2.4 LPA). Offers of Rs 50,000+/month for zero-experience work-from-home roles are bait.",
        "severity": "high"
    },
    {
        "id": 6,
        "category": "Urgency Traps",
        "icon": "⏰",
        "tip": "Ignore 2-hour deadline pressure tactics",
        "detail": "Legitimate companies give 5-7 business days to review an offer letter. Any recruiter demanding acceptance or payment within hours is using psychological pressure — a classic fraud tactic.",
        "severity": "medium"
    },
    {
        "id": 7,
        "category": "Bank Security",
        "icon": "🏦",
        "tip": "Never share OTPs, passwords, or banking PINs",
        "detail": "Employers only need your bank Account Number and IFSC Code for salary setup. Anyone requesting your OTP, netbanking password, debit card PIN, or UPI PIN is committing bank fraud.",
        "severity": "critical"
    },
    {
        "id": 8,
        "category": "WhatsApp / Telegram",
        "icon": "💬",
        "tip": "Be wary of job offers only on WhatsApp or Telegram",
        "detail": "Major Indian corporations use official ATS portals (Naukri, LinkedIn, official careers pages) for recruitment. Entire hiring processes conducted on WhatsApp are a strong scam signal.",
        "severity": "high"
    },
    {
        "id": 9,
        "category": "Legal Threats",
        "icon": "⚖️",
        "tip": "Fake FIR / blacklisting threats have no legal basis",
        "detail": "Declining a job offer is your constitutional right in India. No recruiter or agency can file an FIR against you, blacklist you from job portals, or take legal action for refusing an offer.",
        "severity": "medium"
    },
    {
        "id": 10,
        "category": "Emergency Response",
        "icon": "🆘",
        "tip": "Call 1930 immediately if you lose money",
        "detail": "India's Cyber Crime Helpline 1930 (MHA) can freeze the scammer's bank account within the first 2 hours (Golden Hour). Also file at: https://cybercrime.gov.in/",
        "severity": "critical"
    }
]

AWARENESS_CONTENT_DATA = {
    "scam_types": [
        {
            "name": "Fee / Deposit Fraud",
            "description": "Fraudsters pose as legitimate HR personnel and demand registration fees, laptop deposits, uniform charges, or security deposits before employment.",
            "warning_signs": ["Any upfront payment demanded", "UPI/Google Pay payment requested", "Refundable deposit promises"],
            "how_to_report": "Call 1930 or file at cybercrime.gov.in"
        },
        {
            "name": "Task Earning / YouTube Scam",
            "description": "Victims are recruited to 'like' videos or 'rate' hotels on Telegram, paid small amounts initially, then tricked into depositing thousands in 'VIP task recharges'.",
            "warning_signs": ["Work from Telegram groups", "Daily payment promises", "VIP task recharge requirements", "Withdrawal blocks after deposit"],
            "how_to_report": "Call 1930 immediately and preserve all Telegram/WhatsApp chat history"
        },
        {
            "name": "Fake Offer Letter Fraud",
            "description": "Forged offer letters mimicking TCS, Infosys, Wipro, Amazon India are sent to extract security deposits or personal documents for identity theft.",
            "warning_signs": ["Gmail/Yahoo recruiter address", "Spelling errors in letter", "Missing CIN/GSTIN", "No interview process"],
            "how_to_report": "Verify CIN at mca.gov.in and report fake company at cybercrime.gov.in"
        },
        {
            "name": "Data Entry / Typing Scam",
            "description": "Promises of Rs 25,000-50,000/month for home-based manuscript typing, followed by demands for agreement fees and later 'error correction' fines.",
            "warning_signs": ["Rs 30,000+/month for typing work", "Software login fee required", "Error penalty clauses", "No proper company registration"],
            "how_to_report": "Report to local cyber cell and file complaint at cybercrime.gov.in"
        },
        {
            "name": "Airport / Government Job Scam",
            "description": "Fake agencies advertise airport ground staff, railway, or government jobs requiring 'gate pass fees', 'medical fees', or 'training fees'.",
            "warning_signs": ["Payment for security gate pass", "Uniform measurement fee", "No official government notification", "Gmail recruiter contact"],
            "how_to_report": "Verify with official airline/airport HR or Railway Recruitment Board websites"
        }
    ],
    "legal_framework": {
        "applicable_laws": [
            {"law": "IT Act 2000 Section 66D", "description": "Punishment for cheating by personation using computer resource — up to 3 years imprisonment"},
            {"law": "IPC Section 420", "description": "Cheating and dishonestly inducing delivery of property — up to 7 years imprisonment"},
            {"law": "IPC Section 406", "description": "Criminal breach of trust — up to 3 years imprisonment"},
            {"law": "IPC Section 384", "description": "Extortion — up to 3 years imprisonment (covers fake FIR threats)"}
        ],
        "victim_rights": [
            "Candidates have the absolute right to decline any job offer without legal consequences",
            "No recruiter can legally blacklist you from job portals",
            "Employers cannot demand any fee at any stage of genuine recruitment",
            "You can report fraud even if you voluntarily paid (you were deceived)"
        ]
    },
    "emergency_contacts": [
        {"name": "National Cyber Crime Helpline", "number": "1930", "available": "24/7"},
        {"name": "Cyber Crime Portal", "url": "https://cybercrime.gov.in", "type": "Online Complaint"},
        {"name": "MCA Company Verification", "url": "https://www.mca.gov.in", "type": "Verify Company CIN"},
        {"name": "Police Emergency", "number": "100", "available": "24/7"}
    ],
    "safe_apply_checklist": [
        "Recruiter uses official business domain (@company.com, not @gmail.com)",
        "Strict Zero Upfront Fee — no deposit, uniform, gate pass, or training charges",
        "Proper multi-stage interview process conducted",
        "Valid Corporate CIN verified on MCA portal",
        "No OTP or bank credentials requested",
        "Market-realistic compensation (3.5-7.5 LPA for IT freshers)",
        "Physical corporate office address verifiable on Google Maps",
        "Verified against JobShield Syndicate Database",
        "No artificial 2-hour urgency deadlines",
        "Zero threats of FIR or legal action for declining"
    ]
}


@app.get("/api/quiz")
def get_quiz_questions(
    category: Optional[str] = Query(None, description="Filter by category"),
    difficulty: Optional[str] = Query(None, description="Filter by difficulty: easy, medium, hard"),
    limit: Optional[int] = Query(10, description="Number of questions to return")
):
    """
    Returns the interactive job scam awareness quiz questions.
    Used by the Learn & Quiz page to power the self-assessment tool.
    """
    questions = QUIZ_QUESTIONS_DATA.copy()
    if category:
        questions = [q for q in questions if q["category"].lower() == category.lower()]
    if difficulty:
        questions = [q for q in questions if q["difficulty"].lower() == difficulty.lower()]
    return {
        "total": len(questions),
        "questions": questions[:limit],
        "categories": list({q["category"] for q in QUIZ_QUESTIONS_DATA}),
        "source": "JobShield Cyber Awareness Lab v2.0"
    }


@app.get("/api/tips")
def get_safety_tips(
    category: Optional[str] = Query(None, description="Filter tips by category"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium")
):
    """
    Returns curated job scam safety tips for Indian job seekers.
    Covers email verification, fee policy, document checks, and emergency response.
    """
    tips = SAFETY_TIPS_DATA.copy()
    if category:
        tips = [t for t in tips if category.lower() in t["category"].lower()]
    if severity:
        tips = [t for t in tips if t["severity"].lower() == severity.lower()]
    return {
        "total": len(tips),
        "tips": tips,
        "categories": list({t["category"] for t in SAFETY_TIPS_DATA}),
        "source": "JobShield Safety Guidelines — Updated Oct 2026"
    }


@app.get("/api/awareness")
def get_awareness_content():
    """
    Returns full awareness education content including scam types, legal framework,
    victim rights, emergency contacts, and safe-apply checklist.
    """
    return {
        **AWARENESS_CONTENT_DATA,
        "quiz_endpoint": "/api/quiz",
        "tips_endpoint": "/api/tips",
        "source": "JobShield Cyber Awareness Module v2.0",
        "last_updated": "2026-10-22"
    }



@app.get("/api/samples/{sample_name}")
def get_sample_letter(sample_name: str):
    """Provides sample offer letters for 1-click evaluation."""
    samples_dir = BACKEND_DIR / "samples"
    file_map = {
        "genuine": "genuine_offer_letter.txt",
        "scam": "scam_offer_letter.txt",
        "suspicious": "suspicious_offer_letter.txt"
    }
    target = file_map.get(sample_name.lower())
    if not target or not (samples_dir / target).exists():
        raise HTTPException(status_code=404, detail="Sample not found.")
    with open(samples_dir / target, "r", encoding="utf-8") as f:
        content = f.read()
    return {"sample": sample_name, "filename": target, "content": content}


# -------------------------------------------------------------
# Frontend Static Files & SPA Routing
# -------------------------------------------------------------
if FRONTEND_DIR.exists():
    # Direct HTML page handlers to guarantee clean routing
    @app.get("/")
    def serve_home():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/verify.html")
    def serve_verify():
        return FileResponse(FRONTEND_DIR / "verify.html")


    @app.get("/learn.html")
    def serve_learn():
        return FileResponse(FRONTEND_DIR / "learn.html")

    @app.get("/help.html")
    def serve_help():
        return FileResponse(FRONTEND_DIR / "help.html")

    @app.get("/report-card.html")
    def serve_report_card():
        card_file = FRONTEND_DIR / "report-card.html"
        if not card_file.exists():
            raise HTTPException(status_code=404, detail="report-card.html not found")
        return FileResponse(card_file)

    # Static files mount for CSS, JS, Images
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    print(f"Starting JobShield server at http://{HOST}:{PORT}")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False)
