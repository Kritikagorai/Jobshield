"""
scoring.py
----------
Combines forensic verification rules, entity cross-checks, Scikit-learn ML probabilities,
domain reputation, psychological pressure analysis, and community reports into
one unified, explainable Final Trust Score (0 to 100).

Guidelines:
- Uses wording 'High scam probability', never absolute or accusatory language.
- Produces plain-language explanations with severity ratings and UI icons.
- Highlights a Critical Red Banner whenever payment or personal data is demanded.
"""

from typing import Dict, Any, List, Optional
import re
import database
from .privacy import mask_sensitive_text
from .red_flags import scan_red_flags
from .company_registry import verify_company_credentials
from .email_domain import analyze_domain, is_free_email
from .pressure_meter import calculate_pressure_score
from .similarity import find_similar_scam_templates
from .salary_check import evaluate_salary_benchmark
from .ml_model import scam_classifier


# ---------------------------------------------------------------------------
# Known legitimate Indian corporate and MNC email domains
# These receive a POSITIVE trust signal when used as recruiter email domains
# ---------------------------------------------------------------------------
KNOWN_CORPORATE_DOMAINS = {
    # Top Indian IT companies
    "tcs.com", "infosys.com", "wipro.com", "hcltech.com", "hcl.com",
    "techmahindra.com", "mphasis.com", "hexaware.com", "ltimindtree.com",
    "lntinfotech.com", "niit.com", "mastek.com", "persistent.com",
    "cyient.com", "kpit.com", "zensar.com", "sasken.com", "sonata-software.com",
    "tataelxsi.com", "infobeams.com", "birlasoft.com",
    # MNCs with India presence
    "accenture.com", "capgemini.com", "cognizant.com", "ibm.com",
    "oracle.com", "sap.com", "salesforce.com", "google.com",
    "microsoft.com", "amazon.com", "amazon.in", "deloitte.com",
    "pwc.com", "kpmg.com", "ey.com", "mckinsey.com",
    "thoughtworks.com", "publicissapient.com", "dxc.com",
    # Indian banks & financial institutions
    "icicibank.com", "hdfcbank.com", "axisbank.com", "sbi.co.in",
    "bankofbaroda.co.in", "pnb.co.in", "kotak.com", "yesbank.in",
    "indusind.com", "rblbank.com", "bajajfinserv.in",
    # Indian conglomerates & PSUs
    "tatamotors.com", "tatapower.com", "tatachemicals.com",
    "relianceind.com", "ril.com", "jio.com", "adag.com",
    "adani.com", "mahindra.com", "godrej.com", "bajaj.com",
    "hero.com", "heromotocorp.com", "bhartiairtel.com", "airtel.in",
    "ongc.co.in", "bpcl.in", "iocl.com", "gail.com",
    # Indian startups & unicorns
    "flipkart.com", "myntra.com", "meesho.com", "nykaa.com",
    "zepto.in", "blinkit.com", "swiggy.in", "zomato.com",
    "ola.com", "olacabs.com", "paytm.com", "phonepe.com",
    "razorpay.com", "freshworks.com", "zoho.in", "zerodha.com",
    "groww.in", "upstox.com", "credclub.com", "sharechat.com",
    # EdTech & Healthcare
    "byjus.com", "unacademy.com", "vedantu.com", "apollohospitals.com",
    "fortishealthcare.com", "manipalhospitals.com",
}

# Official career portal URL patterns that signal legitimate hiring
CORPORATE_CAREER_URL_PATTERNS = [
    r'careers\.(?:infosys|tcs|wipro|hcltech|techmahindra|amazon|google|microsoft|accenture|capgemini|cognizant|deloitte|ibm|oracle|flipkart|zomato|swiggy|razorpay|freshworks|zoho|myntra|nykaa|paytm|bajajfinserv|hdfc|icici|axis)\.',
    r'(?:infosys|tcs|wipro|hcltech|techmahindra|amazon|google|microsoft|accenture|capgemini|cognizant|deloitte|ibm|oracle|flipkart|zomato|swiggy|razorpay|freshworks|zoho|myntra|nykaa|paytm|hdfc|icici)\.(?:com|in|co\.in)/(?:careers|jobs|recruitment|hiring)',
    r'(?:naukri|linkedin|indeed|instahyre|iimjobs|shine|hirist|cutshort)\.com',
    r'campus-recruitment@|careers@|hr@|recruitment@|talent@|staffing@',
]


def calculate_comprehensive_trust_score(
    text: str = "",
    url: str = "",
    email: str = "",
    phone: str = "",
    extracted_entities: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main multimodal scoring function.
    Aggregates all 8 detection pillars into a single explainable Trust Score.
    """
    combined_content = f"{text}\n{url}\n{email}\n{phone}".strip()
    text_lower = combined_content.lower()

    score = 80
    reasons: List[Dict[str, Any]] = []
    red_banner_warning: Optional[str] = None

    # -----------------------------------------------------------------------
    # PRE-SCREEN: Detect known corporate domain (email or URL) — strong positive
    # -----------------------------------------------------------------------
    sender_domain = ""
    if email and "@" in email:
        sender_domain = email.split("@")[-1].strip().lower()
    elif url:
        from .email_domain import extract_domain
        sender_domain = extract_domain(url)

    is_known_corporate_domain = sender_domain in KNOWN_CORPORATE_DOMAINS

    # Check career URL patterns for official corporate portals
    has_official_career_url = False
    if url or text:
        check_str = (url + " " + text).lower()
        has_official_career_url = any(
            re.search(pat, check_str, re.IGNORECASE)
            for pat in CORPORATE_CAREER_URL_PATTERNS
        )

    # Apply early bonus for verified corporate domain or official career URL
    if is_known_corporate_domain:
        score += 20
        reasons.append({
            "severity": "low",
            "icon": "check-circle",
            "title": f"Official Corporate Email Domain Verified",
            "description": f"Recruiter email uses '@{sender_domain}', a verified domain of a known Indian/MNC employer. This is a strong positive indicator."
        })

    if has_official_career_url and not is_known_corporate_domain:
        score += 10
        reasons.append({
            "severity": "low",
            "icon": "check-circle",
            "title": "Official Career Portal / Job Board Detected",
            "description": "The job references an official corporate career site or a verified job board (Naukri, LinkedIn, Indeed), consistent with legitimate hiring."
        })

    zero_fee_phrases = [
        "not required to pay", "zero-fee", "zero fee", "no payment",
        "free of charge", "does not charge", "never asks for money",
        "zero-fee recruitment policy", "borne fully by"
    ]
    has_zero_fee_statement = any(p in text_lower for p in zero_fee_phrases)

    # 2. Rule-Based Red Flags (Payment, Data Theft, Tasks, Threats)
    flag_analysis = scan_red_flags(combined_content)

    if flag_analysis["has_payment_demand"] and not has_zero_fee_statement:
        score -= 45
        red_banner_warning = "CRITICAL ALERT: This communication demands money or a security deposit. Genuine employers NEVER charge candidates for jobs or equipment."
        reasons.append({
            "severity": "critical",
            "icon": "alert-triangle",
            "title": "Payment / Security Deposit Demanded",
            "description": "Detected upfront monetary or courier deposit demands. Genuine Indian corporations never charge candidate fees."
        })
    elif has_zero_fee_statement:
        score += 15
        reasons.append({
            "severity": "low",
            "icon": "check-circle",
            "title": "Zero-Fee Policy Confirmed",
            "description": "Offer explicitly confirms zero candidate fees, matching authentic corporate recruitment standards."
        })

    if flag_analysis["has_data_theft"]:
        score -= 25
        if not red_banner_warning:
            red_banner_warning = "WARNING: Request for sensitive financial documents or OTPs detected. Never share blank cheques or banking credentials."
        reasons.append({
            "severity": "critical",
            "icon": "shield-alert",
            "title": "Sensitive Personal / Banking Data Demanded",
            "description": "Detected requests for bank passbooks, cheques, or OTPs. High risk of identity theft and financial fraud."
        })

    # Other flag categories
    for flag in flag_analysis.get("flags", []):
        cat = flag["category"]
        if cat == "TASK_SCAM":
            score -= 30
            reasons.append({
                "severity": "critical",
                "icon": "cpu",
                "title": flag["title"],
                "description": flag["description"]
            })
        elif cat == "LEGAL_INTIMIDATION":
            score -= 25
            reasons.append({
                "severity": "critical",
                "icon": "shield-alert",
                "title": flag["title"],
                "description": flag["description"]
            })
        elif cat == "TELEGRAM_WHATSAPP_REDIRECT":
            score -= 20
            reasons.append({
                "severity": "high",
                "icon": "message-circle",
                "title": flag["title"],
                "description": flag["description"]
            })
        elif cat == "NO_INTERVIEW_DIRECT_OFFER":
            score -= 20
            reasons.append({
                "severity": "medium",
                "icon": "message-circle",
                "title": flag["title"],
                "description": flag["description"]
            })
        elif cat == "SUSPICIOUS_WFH_INCOME":
            score -= 15
            reasons.append({
                "severity": "medium",
                "icon": "alert-triangle",
                "title": flag["title"],
                "description": flag["description"]
            })

    # 3. Domain & Email Verification
    domain_analysis = analyze_domain(sender_domain)
    if domain_analysis.get("is_free_email") and not is_known_corporate_domain:
        score -= 20
        reasons.append({
            "severity": "medium",
            "icon": "mail",
            "title": "Free Public Email Provider Used",
            "description": f"Recruiter contacted from a free public domain (@{domain_analysis['domain']}) instead of an official corporate mailbox."
        })

    if domain_analysis.get("has_suspicious_tld"):
        score -= 20
        reasons.append({
            "severity": "medium",
            "icon": "globe",
            "title": "High-Risk Domain Extension",
            "description": f"Domain ends with '{domain_analysis['domain']}', a top-level extension frequently used for throwaway scam pages."
        })

    if domain_analysis.get("is_typosquat"):
        score -= 35
        reasons.append({
            "severity": "critical",
            "icon": "shield-alert",
            "title": f"Typosquatting Mimicking {domain_analysis.get('target_brand')}",
            "description": domain_analysis.get("reasons", ["Domain mimics a legitimate corporate brand."])[0]
        })

    # 4. Psychological Pressure & Urgency
    pressure = calculate_pressure_score(combined_content)
    if pressure["pressure_score"] >= 35:
        score -= int(pressure["pressure_score"] * 0.4)
        reasons.append({
            "severity": "critical" if pressure["pressure_score"] >= 60 else "high",
            "icon": "clock",
            "title": f"Psychological Pressure Tactics ({pressure['pressure_level']} Level)",
            "description": pressure["advice"]
        })

    # 5. Company Registry & Impersonation Verification
    entities = extracted_entities or {}
    claimed_company = entities.get("company_name")
    cin = entities.get("cin")
    gstin = entities.get("gstin")

    # Build sender_email string safely (entities["emails"] items can be dicts)
    _entity_emails = entities.get("emails", [])
    _first_entity_email = None
    if _entity_emails:
        _first = _entity_emails[0]
        _first_entity_email = _first.get("email") if isinstance(_first, dict) else str(_first)

    comp_check = verify_company_credentials(
        claimed_name=claimed_company,
        provided_cin=cin,
        provided_gstin=gstin,
        sender_email=email or _first_entity_email
    )

    if comp_check.get("found_in_registry"):
        if comp_check.get("is_impersonation"):
            score -= 35
            for disc in comp_check.get("discrepancies", []):
                reasons.append({
                    "severity": "critical",
                    "icon": "shield-alert",
                    "title": "Corporate Impersonation Attack",
                    "description": disc
                })
        elif comp_check.get("status") == "FLAGGED_FAKE":
            score -= 40
            reasons.append({
                "severity": "critical",
                "icon": "database",
                "title": "Known Fraudulent Entity Listed in Registry",
                "description": f"'{comp_check.get('company_name')}' is already flagged in the community fraud database."
            })
        elif comp_check.get("status") == "VERIFIED_GENUINE" and not domain_analysis.get("is_free_email"):
            score += 15
            reasons.append({
                "severity": "low",
                "icon": "check-circle",
                "title": f"Verified Employer: {comp_check.get('company_name')}",
                "description": "Corporate registration and official domain match verified Ministry of Corporate Affairs records."
            })

    # 6. Scikit-Learn Machine Learning Classifier
    is_genuine_corp = (
        comp_check.get("status") == "VERIFIED_GENUINE" and not comp_check.get("is_impersonation")
    ) or is_known_corporate_domain

    ml_res = scam_classifier.predict(combined_content)

    if ml_res.get("is_scam") and ml_res.get("scam_probability", 0) >= 0.55 and not is_genuine_corp:
        ml_prob = ml_res["scam_probability"]
        # Reduce ML penalty weight when there are also strong positive signals
        ml_penalty_weight = 0.20 if (is_known_corporate_domain or has_official_career_url) else 0.25
        score -= int(ml_prob * ml_penalty_weight * 100)
        reasons.append({
            "severity": "high",
            "icon": "cpu",
            "title": f"AI Pattern Detection ({round(ml_prob * 100)}% Scam Probability)",
            "description": f"NLP model identified vocabulary and patterns closely matching real-world employment fraud. Top keywords: {', '.join(ml_res.get('top_features', [])[:3])}."
        })

    # 7. Semantic Template Similarity Matching
    similar_templates = find_similar_scam_templates(combined_content, top_n=1)
    if similar_templates and not is_genuine_corp:
        top_tpl = similar_templates[0]
        if top_tpl["similarity_pct"] >= 25.0:
            score -= int(top_tpl["similarity_pct"] * 0.25)
            reasons.append({
                "severity": "high",
                "icon": "file-text",
                "title": f"Template Match: {top_tpl['title']} ({top_tpl['similarity_pct']}% Match)",
                "description": f"Text shares phrasing with a known fraud template reported by {top_tpl['report_count']} victims."
            })

    # 8. Database Cross-Check against Community Reports
    linked_query: Dict[str, str] = {}
    if phone:
        linked_query["phone"] = phone
    elif entities.get("phones"):
        linked_query["phone"] = entities["phones"][0]

    if email:
        linked_query["email"] = email
    elif entities.get("emails"):
        linked_query["email"] = entities["emails"][0]

    if entities.get("upi_ids"):
        linked_query["upi_id"] = entities["upi_ids"][0]

    linked_reports = database.db_manager.find_linked_reports(linked_query) if linked_query else []
    if linked_reports:
        score -= 35
        reasons.append({
            "severity": "critical",
            "icon": "database",
            "title": f"Directly Linked to {len(linked_reports)} Existing Scam Report(s)",
            "description": f"Contact identifiers match {len(linked_reports)} previously submitted scam complaints in the database."
        })

    # Bound final score between 5 and 98
    final_score = max(5, min(98, score))

    # Determine Verdict, Risk Category & Confidence
    if not combined_content.strip():
        risk_category = "Unable to determine"
        verdict = "Unable to determine"
        confidence = "Low"
    elif final_score >= 75:
        risk_category = "Low apparent risk"
        verdict = "Safe / Likely Genuine"
        confidence = "High" if final_score >= 88 else "Moderate"
    elif final_score >= 55:
        risk_category = "Needs verification"
        verdict = "Probably Legitimate – Verify Details"
        confidence = "Moderate"
    elif final_score >= 40:
        risk_category = "Needs verification"
        verdict = "Suspicious – Exercise Caution"
        confidence = "Moderate"
    else:
        risk_category = "High risk"
        verdict = "High scam probability"
        confidence = "High" if final_score <= 25 else "Moderate"

    if not reasons:
        reasons.append({
            "severity": "low",
            "icon": "check-circle",
            "title": "No Obvious Red Flags Detected",
            "description": "No upfront fee demands, free emails, or known scam links were found in the provided details."
        })

    # Separate Positive Indicators and Warning Signs
    positive_indicators = [
        {"title": r["title"], "description": r["description"]}
        for r in reasons if r.get("severity") == "low"
    ]
    warning_signs = [
        {"title": r["title"], "description": r["description"], "severity": r.get("severity", "medium").upper()}
        for r in reasons if r.get("severity") in ["medium", "high", "critical"]
    ]

    # Recommended Next Steps
    recommended_steps = []
    if final_score < 40:
        recommended_steps.append("Never pay any registration, laptop deposit, training, or courier charge.")
        recommended_steps.append("Never share OTPs, banking PINs, or unmasked Aadhaar/PAN cards.")
        recommended_steps.append("Report this communication to the National Cybercrime Reporting Helpline (1930) or cybercrime.gov.in.")
        recommended_steps.append("Block the suspect contact and preserve chat screenshots as evidence.")
    elif final_score < 70:
        recommended_steps.append("Cross-check the recruiter's official identity on LinkedIn or corporate switchboard.")
        recommended_steps.append("Visit the official career site directly rather than following links in messages.")
        recommended_steps.append("Request written confirmation from an official company email address.")
    else:
        recommended_steps.append("Proceed with normal recruitment screening.")
        recommended_steps.append("Always remember: authentic employers never charge candidates money at any stage.")

    return {
        "trust_score": final_score,
        "score_direction": "Higher is safer (0 = High Scam Risk, 100 = Likely Genuine)",
        "verdict": verdict,
        "risk_category": risk_category,
        "confidence": confidence,
        "red_banner_warning": red_banner_warning,
        "reasons": reasons,
        "positive_indicators": positive_indicators,
        "warning_signs": warning_signs,
        "recommended_next_steps": recommended_steps,
        "ml_analysis": ml_res,
        "pressure_analysis": pressure,
        "company_verification": comp_check,
        "linked_reports_count": len(linked_reports),
        "disclaimer": "JobShield provides probabilistic risk assessments based on pattern recognition and community reports. Always independently verify offers via official corporate channels before sharing money or documents."
    }
