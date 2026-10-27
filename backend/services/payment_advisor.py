"""
payment_advisor.py
------------------
Interactive Red-Flag Advisor answering:
"Should I pay or share this information for this job?"

Analyzes requests involving:
- Upfront registration, processing, gate pass, or interview fees.
- Security deposits for laptops, uniforms, or mandatory training kits.
- Purchasing equipment from specific vendors or designated portals.
- Sensitive banking data: account numbers, cancelled cheques, passbooks.
- UPI IDs and suspicious payment requests.
- Government IDs: Aadhaar and PAN numbers (masked before processing).
- Banking credentials: OTPs, PINs, passwords, CVV (CRITICAL ALARM).

Strict Guidelines:
- Never ask users to submit actual passwords or OTPs.
- Masks sensitive data locally; never logs or stores banking credentials.
- Plain language explanations with practical safer verification steps.
"""

import re
from typing import Dict, Any, List
from .privacy import mask_sensitive_text


RED_FLAG_CATEGORIES = [
    {
        "id": "OTP_PIN_PASSWORD",
        "category": "Banking Credentials / OTP Demand",
        "severity": "CRITICAL_THREAT",
        "badge": "🚨 NEVER SHARE - IMMEDIATE DANGER",
        "regex": r'\b(?:otp|one\s*time\s*password|atm\s*pin|upi\s*pin|net\s*banking\s*password|cvv|security\s*code|card\s*expiry)\b',
        "title": "Demanding OTP, PIN, or Password",
        "why_unsafe": (
            "No legitimate employer, bank, government agency, or HR recruiter will EVER ask for your OTP, "
            "UPI PIN, ATM PIN, or banking password. Sharing an OTP gives scammers immediate access to drain your bank account."
        ),
        "what_to_do_next": "Refuse immediately. Do NOT enter or share your PIN/OTP. Check your bank statement and report to Helpline 1930.",
        "safer_verification": "Report the incident to the National Cybercrime Portal (cybercrime.gov.in) and call your bank to block unauthorized netbanking."
    },
    {
        "id": "FEE_DEPOSIT",
        "category": "Upfront Fees / Security Deposit",
        "severity": "CRITICAL",
        "badge": "🛑 DO NOT PAY - SCAM WARNING",
        "regex": r'(?:refundable|security|gate\s*pass|badge|uniform|courier|laptop|training|registration|processing|medical\s*checkup|stamp\s*duty|vpn\s*license|document)\s*(?:fee|deposit|charge|cost|amount|challan)',
        "title": "Demanding Upfront Fee or Security Deposit",
        "why_unsafe": (
            "Genuine employers NEVER charge candidates for job applications, laptops, uniform deposits, or training kits. "
            "Under Indian labor guidelines and Ministry of Corporate Affairs norms, recruitment expenses are borne by the company. "
            "Once a victim pays, scammers usually demand further 'clearance' fees or vanish entirely."
        ),
        "what_to_do_next": "Do not transfer any money. Refuse politely and ask for an official corporate zero-fee recruitment policy.",
        "safer_verification": "Check the company's official career portal (e.g. tcs.com/careers). Legitimate corporations maintain strict zero-fee policies."
    },
    {
        "id": "EQUIPMENT_VENDOR_PURCHASE",
        "category": "Mandatory Vendor Equipment Purchase",
        "severity": "HIGH",
        "badge": "🛑 DO NOT BUY",
        "regex": r'(?:buy|purchase|order)\s*(?:from|through)?\s*(?:our|specified|approved|designated)?\s*(?:vendor|seller|store|portal|website|link)|reimburse\s*(?:later|in\s*first\s*month|after\s*joining)',
        "title": "Mandatory Equipment Purchase from Specified Vendor",
        "why_unsafe": (
            "A common scam asks new hires to buy hardware/software from a specific fraudulent website with the promise of "
            "future reimbursement. The website is controlled by scammers, and the equipment or refund never arrives."
        ),
        "what_to_do_next": "Do not purchase items from unverified vendor links. Legitimate companies courier company-managed assets directly.",
        "safer_verification": "Confirm with corporate IT departments directly. Real employers ship pre-configured equipment at zero candidate cost."
    },
    {
        "id": "UPI_PAYMENT_REQUEST",
        "category": "UPI / QR Code Payment Solicitation",
        "severity": "HIGH",
        "badge": "⚠️ DO NOT SEND PAYMENT",
        "regex": r'(?:pay\s*(?:via|through|to)?\s*(?:gpay|phonepe|paytm|upi)|transfer\s*money\s*to\s*upi|scan\s*(?:this)?\s*qr|@[a-zA-Z0-9.\-_]{3,64})',
        "title": "Payment Requested via UPI, GPay, or PhonePe",
        "why_unsafe": (
            "Enterprise companies process all financial transactions through registered corporate bank accounts via NEFT/RTGS/IMPS, "
            "never via private UPI handles, QR codes, or personal Google Pay numbers."
        ),
        "what_to_do_next": "Never scan QR codes or approve UPI collect requests. Scanning a QR code is for sending money, not receiving it.",
        "safer_verification": "Verify if the UPI handle belongs to a personal account. Legitimate employers never collect candidate fees via UPI."
    },
    {
        "id": "AADHAAR_PAN_SHARING",
        "category": "Premature Identity Document Sharing",
        "severity": "MEDIUM",
        "badge": "⚠️ VERIFY BEFORE SHARING",
        "regex": r'(?:aadhaar\s*(?:card|copy|front|back|number)|pan\s*(?:card|number|copy)|send\s*identity\s*proof)',
        "title": "Request for Aadhaar or PAN Card Copy",
        "why_unsafe": (
            "While genuine employers do require PAN and Aadhaar for payroll and Provident Fund (UAN) registration, "
            "scammers collect unmasked identity documents to apply for fraudulent personal loans or open mule bank accounts."
        ),
        "what_to_do_next": "Never share unmasked Aadhaar over WhatsApp or Telegram. If required for verification, provide a Masked Aadhaar (showing only last 4 digits) with a purpose watermark.",
        "safer_verification": "Upload documents only through official corporate HR portals (e.g., Workday, SuccessFactors, Darwinbox), not informal messaging apps."
    },
    {
        "id": "BANK_DETAILS_CHEQUE",
        "category": "Cancelled Cheque / Bank Details Sharing",
        "severity": "MEDIUM",
        "badge": "⚠️ SHARE ONLY ON JOINING DAY",
        "regex": r'(?:cancelled\s*cheque|blank\s*cheque|bank\s*passbook\s*photo|account\s*number\s*and\s*ifsc)',
        "title": "Request for Bank Account Details or Cancelled Cheque",
        "why_unsafe": (
            "Asking for bank passbook copies or cancelled cheques before an interview or formal joining date is a red flag. "
            "Scammers use these details for account-takeover attacks or fraud linkage."
        ),
        "what_to_do_next": "Never share blank cheques. If required on your official joining day for salary credit, write 'CANCELLED - FOR SALARY ACCOUNT ONLY' across the face.",
        "safer_verification": "Submit bank details only on or after your official joining date via the verified enterprise HRMS portal."
    }
]


def evaluate_payment_safety(input_text: str) -> Dict[str, Any]:
    """
    Evaluates whether a job request involves unsafe payments or identity data sharing.
    Answers: "Should I pay or share this information for this job?"
    """
    if not input_text or not input_text.strip():
        return {
            "verdict": "CANNOT_DETERMINE",
            "verdict_title": "No Details Provided",
            "overall_severity": "SAFE",
            "should_pay": False,
            "should_share": False,
            "detected_warnings": [],
            "action_checklist": ["Paste the message, email, or offer text describing the payment or data request."],
            "masked_content": ""
        }

    # Mask sensitive data before inspecting/storing
    masked_text = mask_sensitive_text(input_text)
    text_lower = input_text.lower()

    detected_warnings = []
    has_critical_threat = False
    has_payment_demand = False
    has_data_sharing = False

    for item in RED_FLAG_CATEGORIES:
        pattern = item["regex"]
        if re.search(pattern, text_lower, re.IGNORECASE):
            if item["severity"] == "CRITICAL_THREAT":
                has_critical_threat = True
            if item["id"] in ["FEE_DEPOSIT", "UPI_PAYMENT_REQUEST", "EQUIPMENT_VENDOR_PURCHASE"]:
                has_payment_demand = True
            if item["id"] in ["OTP_PIN_PASSWORD", "AADHAAR_PAN_SHARING", "BANK_DETAILS_CHEQUE"]:
                has_data_sharing = True

            detected_warnings.append({
                "id": item["id"],
                "category": item["category"],
                "severity": item["severity"],
                "badge": item["badge"],
                "title": item["title"],
                "why_unsafe": item["why_unsafe"],
                "what_to_do_next": item["what_to_do_next"],
                "safer_verification": item["safer_verification"]
            })

    # Determine overall decision & severity
    if has_critical_threat:
        verdict = "DO_NOT_SHARE_CRITICAL"
        verdict_title = "CRITICAL ALERT: Never Share Banking Passwords or OTPs!"
        overall_severity = "CRITICAL_THREAT"
        should_pay = False
        should_share = False
        primary_advice = "DO NOT SHARE THIS INFORMATION. This is an active financial theft attempt. Legitimate companies never request OTPs or PINs."
    elif has_payment_demand:
        verdict = "DO_NOT_PAY"
        verdict_title = "DO NOT PAY: High Scam Probability!"
        overall_severity = "CRITICAL"
        should_pay = False
        should_share = False
        primary_advice = "DO NOT PAY ANY MONEY. Genuine employers in India never charge candidates for registration, laptops, uniforms, or training."
    elif has_data_sharing:
        verdict = "EXERCISE_CAUTION"
        verdict_title = "EXERCISE CAUTION: Verify Before Sharing Sensitive Documents"
        overall_severity = "HIGH"
        should_pay = False
        should_share = False
        primary_advice = "Do not share unmasked identity or banking documents over informal messaging apps like WhatsApp or Telegram."
    else:
        verdict = "NO_OBVIOUS_RED_FLAGS"
        verdict_title = "No Monetary Demands or Credential Requests Detected"
        overall_severity = "SAFE"
        should_pay = False  # Still False by default because genuine jobs never require candidate pay
        should_share = True
        primary_advice = "The provided text does not contain requests for fees, deposits, or banking credentials. Continue with standard precautions."

    # Practical Action Checklist
    action_checklist = []
    if should_pay is False and (has_payment_demand or has_critical_threat):
        action_checklist.append("1. Do not transfer any funds via UPI, NetBanking, GPay, or payment links.")
        action_checklist.append("2. Ask the recruiter for the company's official MCA Corporate Identification Number (CIN) and official website.")
        action_checklist.append("3. Cross-reference the recruiter's email domain against the company's official career portal.")
        action_checklist.append("4. If they threaten legal action or police complaints under IPC 420, it is 100% fake extortion; block the contact.")
    else:
        action_checklist.append("1. Verify the recruiter's name and role on LinkedIn and corporate directory.")
        action_checklist.append("2. Share documents only through secure official corporate HRMS portals, never on WhatsApp.")
        action_checklist.append("3. Use Masked Aadhaar (e-Aadhaar showing only the last 4 digits) when identity proof is required.")

    risk_level_mapped = "CRITICAL" if has_critical_threat else ("HIGH" if has_payment_demand else ("MEDIUM" if has_data_sharing else "LOW"))

    return {
        "verdict": verdict,
        "verdict_title": verdict_title,
        "overall_severity": overall_severity,
        "risk_level": risk_level_mapped,
        "safe_to_proceed": overall_severity == "SAFE",
        "critical_warning_otp": has_critical_threat,
        "should_pay": should_pay,
        "should_share": should_share,
        "primary_advice": primary_advice,
        "advisory": primary_advice,
        "warnings_count": len(detected_warnings),
        "detected_warnings": detected_warnings,
        "detected_red_flags": detected_warnings,
        "action_checklist": action_checklist,
        "actionable_guidance": action_checklist + ["Legal Reference: Ministry of Labour & Employment guidelines prohibit recruitment fees."],
        "masked_content": masked_text,
        "safer_verification_steps": [
            "Always apply through official corporate career portals (e.g. company.com/careers).",
            "Genuine Indian employers adhere to zero-fee hiring under Indian labor regulations.",
            "If financial loss has already occurred, immediately call the National Cyber Crime Helpline at 1930."
        ],
        "disclaimer": "JobShield provides advisory guidance based on cyber safety best practices. Genuine employers never charge candidates money under any pretext."
    }
