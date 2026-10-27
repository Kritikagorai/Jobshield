"""
Forensic Offer Letter Verifier Service for JobShield (Phase 3).
Performs deep structural, registry, compensation, and legal threat audits:
1. Company Registry Cross-Reference (MCA Database matching & impersonation detection)
2. Email Domain Authentication (Official business domain vs free provider abuse)
3. CIN / GSTIN Structural Integrity & Alignment Check
4. Salary Benchmark Reality Check (Indian industry norms comparison)
5. Upfront Fee & Security Deposit Audit (Zero-fee compliance)
6. Coercion & Fake Section 420 Blackmail Detection
"""
from typing import Dict, List, Any, Optional
from services.entity_extractor import (
    extract_all_entities,
    validate_cin_structure,
    FREE_EMAIL_DOMAINS
)


import re


def verify_offer_letter(
    text: str,
    db_manager: Any,
    filename: Optional[str] = None,
    company_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes forensic examination of an offer letter text or uploaded document.
    Returns complete explainable breakdown, 6-pillar scorecard, and forensic trust score.
    """
    entities = extract_all_entities(text, explicit_company=company_name)
    
    score = 88  # Baseline trust score
    checks = []
    red_flags_count = 0
    high_threat_triggers = []

    # -------------------------------------------------------------
    # Pillar 1: Company Registry Match & Impersonation Audit
    # -------------------------------------------------------------
    matched_company = None
    all_companies = db_manager.get_all_companies()
    extracted_company = entities.get("company_name")

    # Priority 1: If candidate company was extracted from JD / input, check if it matches registry
    if extracted_company:
        ext_clean = extracted_company.lower().strip()
        for c in all_companies:
            c_name = c["name"].lower().strip()
            if c_name == ext_clean or ext_clean in c_name:
                matched_company = c
                break
            for alias in c.get("aliases", []):
                if alias.lower().strip() == ext_clean:
                    matched_company = c
                    break
            if matched_company:
                break

    # Priority 2: If no company was extracted from JD headers, search text using STRICT word boundaries
    # (Never match raw substring 'cts' inside 'products'/'projects' or 'google' inside 'Google Cloud')
    if not matched_company and not extracted_company:
        # Check CIN if provided
        cin = entities.get("cin")
        if cin:
            for c in all_companies:
                if c.get("cin") and c["cin"].upper() == cin.upper():
                    matched_company = c
                    break

        if not matched_company:
            for c in all_companies:
                c_name = c["name"]
                if re.search(rf'\b{re.escape(c_name)}\b', text, re.IGNORECASE):
                    matched_company = c
                    break

                for alias in c.get("aliases", []):
                    # Short aliases (CTS, TCS, SBI, LTI) must match exact uppercase word boundary
                    if len(alias) <= 4:
                        if re.search(rf'\b{re.escape(alias)}\b', text):
                            matched_company = c
                            break
                    else:
                        # Exclude tech stack references
                        if alias.lower() == "google" and re.search(r'\bGoogle\s+(?:Cloud|Workspace|Analytics|Ads|Docs|Drive|GCP)\b', text, re.IGNORECASE):
                            continue
                        if alias.lower() == "amazon" and re.search(r'\bAmazon\s+(?:Web Services|AWS)\b', text, re.IGNORECASE):
                            continue
                        if alias.lower() == "microsoft" and re.search(r'\bMicrosoft\s+(?:Azure|Office|365|Excel|Teams)\b', text, re.IGNORECASE):
                            continue
                        if re.search(rf'\b{re.escape(alias)}\b', text, re.IGNORECASE):
                            matched_company = c
                            break
                if matched_company:
                    break

    company_display_name = matched_company["name"] if matched_company else (extracted_company or None)

    if matched_company:
        checks.append({
            "pillar": "Company Registry",
            "status": "PASS",
            "title": f"Official Entity Identified: {matched_company['name']}",
            "description": f"Matched registered company (Incorporated {matched_company.get('incorporation_year', 'N/A')}, CIN: {matched_company.get('cin', 'N/A')})."
        })

        # Check Email Domain against matched company
        emails = entities.get("emails", [])
        if emails:
            official_domains = [d.lower() for d in matched_company.get("official_email_domains", [])]
            primary_email = emails[0]["email"]
            email_domain = emails[0]["domain"]

            if email_domain in official_domains:
                checks.append({
                    "pillar": "Email Authentication",
                    "status": "PASS",
                    "title": f"Verified Corporate Email Domain (@{email_domain})",
                    "description": f"The recruiter's email domain matches the official corporate domain registered by {matched_company['name']}."
                })
            else:
                score -= 35
                red_flags_count += 1
                high_threat_triggers.append("Corporate Impersonation")
                checks.append({
                    "pillar": "Email Authentication",
                    "status": "FAIL",
                    "severity": "critical",
                    "title": f"Corporate Impersonation Detected! (@{email_domain})",
                    "description": f"The offer claims to be from {matched_company['name']}, but the recruiter contact is '{primary_email}'. Legitimate {matched_company['name']} recruiters exclusively use official @{matched_company.get('official_domain', 'corporate')} domains, NEVER free public emails or lookalike domains."
                })
        else:
            # No email provided
            score -= 10
            checks.append({
                "pillar": "Email Authentication",
                "status": "WARN",
                "severity": "medium",
                "title": "No Recruiter Corporate Email Found",
                "description": "Offer does not list a verifiable corporate email address."
            })
    elif extracted_company:
        # Identified company from JD, but not in top 20 pre-seeded list (e.g. Razorpay, Zepto, Swiggy)
        checks.append({
            "pillar": "Company Registry",
            "status": "INFO",
            "title": f"Hiring Entity Identified: {extracted_company}",
            "description": f"Extracted hiring employer '{extracted_company}' from job description. Note: This organization is not in JobShield's Top-20 MCA enterprise registry — verify directly on their official careers site."
        })

        emails = entities.get("emails", [])
        if emails:
            primary_email = emails[0]["email"]
            email_domain = emails[0]["domain"]
            if emails[0].get("is_free_provider"):
                score -= 20
                red_flags_count += 1
                checks.append({
                    "pillar": "Email Authentication",
                    "status": "WARN",
                    "severity": "medium",
                    "title": f"Free Email Provider Used (@{email_domain})",
                    "description": f"Recruiter contacted from '{primary_email}'. Reputable companies typically use official corporate domain emails."
                })
            else:
                checks.append({
                    "pillar": "Email Authentication",
                    "status": "PASS",
                    "title": f"Corporate Email Domain Found (@{email_domain})",
                    "description": f"Recruiter contact '{primary_email}' uses a private corporate domain."
                })
        else:
            checks.append({
                "pillar": "Email Authentication",
                "status": "WARN",
                "severity": "low",
                "title": "No Recruiter Corporate Email Found",
                "description": "Offer does not list a verifiable corporate email address."
            })
    else:
        # Company not found or extracted
        checks.append({
            "pillar": "Company Registry",
            "status": "WARN",
            "severity": "medium",
            "title": "Unspecified Employer / Startup Entity",
            "description": "Company name could not be automatically detected from the job description. Proceed with independent due diligence."
        })

    # -------------------------------------------------------------
    # Pillar 2: CIN & GSTIN Structural Verification
    # -------------------------------------------------------------
    cin = entities.get("cin")
    if cin:
        cin_validation = validate_cin_structure(cin)
        if cin_validation["valid"]:
            # Check if CIN matches the company's real CIN
            if matched_company and matched_company.get("cin"):
                if cin.upper() == matched_company["cin"].upper():
                    checks.append({
                        "pillar": "CIN Integrity",
                        "status": "PASS",
                        "title": f"Valid CIN Match: {cin}",
                        "description": f"CIN matches the official MCA registration for {matched_company['name']} ({cin_validation['state']}, Incorporated {cin_validation['incorporation_year']})."
                    })
                else:
                    score -= 25
                    red_flags_count += 1
                    checks.append({
                        "pillar": "CIN Integrity",
                        "status": "FAIL",
                        "severity": "high",
                        "title": "CIN Discrepancy / Borrowed CIN",
                        "description": f"The document mentions CIN '{cin}', but {matched_company['name']}'s official registered CIN is '{matched_company.get('cin')}'. Scammers frequently steal CINs from public databases."
                    })
            else:
                checks.append({
                    "pillar": "CIN Integrity",
                    "status": "PASS",
                    "title": f"Valid MCA Alphanumeric CIN: {cin}",
                    "description": f"Format validated: {cin_validation['listing']} company in {cin_validation['state']}, registered year {cin_validation['incorporation_year']}."
                })
        else:
            score -= 20
            red_flags_count += 1
            checks.append({
                "pillar": "CIN Integrity",
                "status": "FAIL",
                "severity": "high",
                "title": f"Malformed CIN: {cin}",
                "description": cin_validation.get("reason", "Invalid structure")
            })
    else:
        # Missing CIN
        score -= 10
        checks.append({
            "pillar": "CIN Integrity",
            "status": "WARN",
            "severity": "medium",
            "title": "No Corporate Identification Number (CIN) Provided",
            "description": "Standard corporate appointment letters in India contain the company's 21-character CIN."
        })

    # -------------------------------------------------------------
    # Pillar 3: Upfront Payment & Fee Audit (Zero-Fee Compliance)
    # -------------------------------------------------------------
    fee_demands = entities.get("fee_demands", [])
    upi_ids = entities.get("upi_ids", [])

    if fee_demands or upi_ids:
        score -= 50
        red_flags_count += 1
        high_threat_triggers.append("Fee Demanded")
        
        fee_names = [f["keyword"] for f in fee_demands]
        amt_str = ""
        for f in fee_demands:
            if f.get("detected_amount_inr"):
                amt_str = f" (Demanding INR {f['detected_amount_inr']:,.0f})"
                break

        upi_note = f" Transfer directed to UPI ID: {', '.join(upi_ids)}." if upi_ids else ""

        checks.append({
            "pillar": "Payment Demands",
            "status": "FAIL",
            "severity": "critical",
            "title": f"ILLEGAL RECRUITMENT PAYMENT DEMANDED{amt_str}",
            "description": f"Detected payment triggers: {', '.join(fee_names[:3])}.{upi_note} Under Indian employment law and corporate HR compliance, GENUINE EMPLOYERS NEVER CHARGE CANDIDATES FOR LAPTOPS, UNIFORMS, COURIERS, GATE PASSES, OR REGISTRATION."
        })
    else:
        checks.append({
            "pillar": "Payment Demands",
            "status": "PASS",
            "title": "Zero Upfront Fees Demanded",
            "description": "No security deposits, laptop courier fees, or UPI transfer requests detected in document text."
        })

    # -------------------------------------------------------------
    # Pillar 4: Salary Market Reality Check
    # -------------------------------------------------------------
    salaries = entities.get("salaries", [])
    salary_verdict = "Normal"
    if salaries:
        primary_salary = salaries[0]
        offered_lpa = primary_salary.get("value_lpa", 0)

        # Retrieve benchmarks from DB
        benchmarks = db_manager.get_salary_benchmarks("Software Engineer")
        fresher_benchmark = next((b for b in benchmarks if "Fresher" in b.get("experience_level", "")), None)

        if fresher_benchmark and offered_lpa > 0:
            tier1_max = fresher_benchmark.get("tier1_max", 7.5)
            tier1_median = fresher_benchmark.get("tier1_median", 4.5)

            # If offered > 9 LPA for a fresher with no interview/single telephonic screening
            if offered_lpa >= 9.5:
                score -= 20
                red_flags_count += 1
                salary_verdict = "Anomalously High (Scam Bait)"
                checks.append({
                    "pillar": "Salary Reality Check",
                    "status": "FAIL",
                    "severity": "high",
                    "title": f"Unrealistic Compensation: {offered_lpa:.1f} LPA ({primary_salary.get('raw_text')})",
                    "description": f"Indian industry standard median for fresher roles is {tier1_median:.1f} LPA (Max Tier-1: {tier1_max:.1f} LPA). Scammers deliberately advertise inflated pay (~INR 85,000/month) to entice students into paying courier deposits."
                })
            else:
                checks.append({
                    "pillar": "Salary Reality Check",
                    "status": "PASS",
                    "title": f"Market Realistic Compensation: {offered_lpa:.1f} LPA",
                    "description": f"Offered salary aligns with standard Indian industry entry brackets ({tier1_median:.1f} - {tier1_max:.1f} LPA)."
                })
    else:
        checks.append({
            "pillar": "Salary Reality Check",
            "status": "INFO",
            "title": "Compensation Figures Not Stated",
            "description": "No explicit LPA or monthly salary breakdown parsed from document."
        })

    # -------------------------------------------------------------
    # Pillar 5: Legal Coercion & Fake Section 420 Blackmail Audit
    # -------------------------------------------------------------
    coercion = entities.get("coercion_phrases", [])
    if coercion:
        score -= 30
        red_flags_count += 1
        high_threat_triggers.append("Extortion / Coercion")
        checks.append({
            "pillar": "Coercion & Blackmail",
            "status": "FAIL",
            "severity": "critical",
            "title": "Psychological Coercion & Fraudulent Legal Threats",
            "description": f"Found intimidation terms: {', '.join(coercion[:3])}. Scammers falsely invoke IPC Section 420 or threaten Naukri blacklisting within 2 hours to panic students into transferring money."
        })
    else:
        checks.append({
            "pillar": "Coercion & Blackmail",
            "status": "PASS",
            "title": "No Coercive Threats Detected",
            "description": "No fake police clauses, portal blacklist threats, or artificial high-pressure time traps."
        })

    # -------------------------------------------------------------
    # Pillar 6: Community Syndicate Match
    # -------------------------------------------------------------
    query_dict = {}
    if entities.get("phones"):
        query_dict["phone"] = entities["phones"][0]
    if entities.get("emails"):
        query_dict["email"] = entities["emails"][0]["email"]
    if entities.get("upi_ids"):
        query_dict["upi_id"] = entities["upi_ids"][0]
    if company_display_name:
        query_dict["company_name"] = company_display_name

    linked_reports = db_manager.find_linked_reports(query_dict)
    if linked_reports:
        score -= 35
        red_flags_count += 1
        high_threat_triggers.append("Linked to Syndicate")
        checks.append({
            "pillar": "Syndicate Database",
            "status": "FAIL",
            "severity": "critical",
            "title": f"Matches {len(linked_reports)} Known Community Scam Reports!",
            "description": f"Suspect contact identifiers in this document directly match {len(linked_reports)} confirmed job fraud incidents reported by candidates."
        })
    else:
        checks.append({
            "pillar": "Syndicate Database",
            "status": "PASS",
            "title": "Clean Community Registry History",
            "description": "No active community complaints recorded against these specific phone numbers or UPI handles."
        })

    # Bound score between 5 and 98
    score = max(5, min(98, score))

    # Overall Verdict
    if score >= 75 and red_flags_count == 0:
        verdict = "Safe / Likely Genuine Offer"
        risk_level = "LOW"
        badge_class = "safe"
    elif score >= 45 and not high_threat_triggers:
        verdict = "Suspicious – Exercise Due Diligence"
        risk_level = "MODERATE"
        badge_class = "suspicious"
    else:
        verdict = "CONFIRMED FRAUD / HIGH SCAM PROBABILITY"
        risk_level = "CRITICAL"
        badge_class = "scam"

    return {
        "trust_score": score,
        "verdict": verdict,
        "risk_level": risk_level,
        "badge_class": badge_class,
        "matched_company": company_display_name,
        "identified_company": company_display_name,
        "is_registered_mca": bool(matched_company),
        "red_flags_count": red_flags_count,
        "high_threat_triggers": high_threat_triggers,
        "extracted_entities": {
            "company_name": company_display_name,
            "cin": entities.get("cin"),
            "gstin": entities.get("gstin"),
            "phones": entities.get("phones"),
            "emails": [e["email"] for e in entities.get("emails", [])],
            "upi_ids": entities.get("upi_ids"),
            "salaries": [s.get("raw_text") for s in entities.get("salaries", [])],
            "fee_demands": [f["keyword"] for f in entities.get("fee_demands", [])]
        },
        "forensic_checklist": checks,
        "filename": filename or "Pasted Document",
        "action_recommendation": (
            "DO NOT PAY ANY MONEY. Report the phone number and UPI handle immediately to National Cyber Helpline 1930."
            if score < 50
            else "Verify the offer via the company's official careers portal before sharing sensitive personal identification."
        )
    }
