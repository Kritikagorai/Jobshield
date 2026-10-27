"""
Cybercrime Complaint Generator Service for JobShield (Phase 7).
Generates ready-to-file legal complaint drafts conforming to
the National Cyber Crime Reporting Portal (cybercrime.gov.in) and
Formal Bank Transaction Freeze notices for victim emergency response.
"""
from datetime import datetime
from typing import Dict, Any


def generate_official_complaint(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a structured complaint text for cybercrime.gov.in and a bank freeze notice.
    """
    complainant_name = data.get("complainant_name", "").strip() or "Concerned Citizen / Job Applicant"
    complainant_phone = data.get("complainant_phone", "").strip() or "N/A"
    complainant_city = data.get("complainant_city", "").strip() or "India"
    
    suspect_name = data.get("suspect_name", "").strip() or "Unknown Fraudulent Recruiter"
    suspect_phone = data.get("suspect_phone", "").strip() or "N/A"
    suspect_email = data.get("suspect_email", "").strip() or "N/A"
    suspect_upi = data.get("suspect_upi", "").strip() or "N/A"
    suspect_company = data.get("suspect_company", "").strip() or "Fake Corporate Entity"
    
    amount_lost = float(data.get("amount_lost") or 0)
    utr_number = data.get("utr_number", "").strip() or "PENDING_BANK_STATEMENT"
    incident_date = data.get("incident_date", "").strip() or datetime.now().strftime("%Y-%m-%d")
    scam_category = data.get("scam_category", "Employment / Job Offer Fraud").strip()
    narrative = data.get("narrative", "").strip() or "The accused posed as an HR recruiter and solicited fraudulent payments."

    # 1. Official National Cybercrime Reporting Portal Draft
    portal_draft = f"""NATIONAL CYBER CRIME REPORTING PORTAL (cybercrime.gov.in)
FORMAL COMPLAINT FILING DRAFT
Category: Online Financial Fraud / Job Fraud
Relevant Legal Sections:
- Section 66D, Information Technology Act, 2000 (Cheating by personation by using computer resource)
- Sections 419, 420, 468, 471 & 506 of IPC / Corresponding BNS Provisions (Cheating, Forgery, Extortion)

I. COMPLAINANT PARTICULARS:
- Full Name: {complainant_name}
- Contact Phone: {complainant_phone}
- Place of Occurrence: {complainant_city}
- Incident Date: {incident_date}

II. SUSPECT / ACCUSED IDENTIFIERS:
- Entity / Company Impersonated: {suspect_company}
- Suspect Recruiter Alias: {suspect_name}
- Suspect Phone / WhatsApp: {suspect_phone}
- Suspect Email Address: {suspect_email}
- Suspect UPI ID / VPA: {suspect_upi}

III. TRANSACTION & FINANCIAL LOSS SUMMARY:
- Total Amount Defrauded: INR {amount_lost:,.2f}
- Transaction Reference / UTR Number: {utr_number}
- Beneficiary Payment Handle: {suspect_upi}

IV. DETAILED NARRATIVE OF THE CRIME:
On {incident_date}, I was targeted by individuals claiming to represent {suspect_company}. 
The perpetrator(s) communicated via {suspect_phone} and {suspect_email}.

Nature of Scam: {scam_category}
Facts of Incident:
{narrative}

Under the false pretense of employment onboarding, mandatory equipment dispatch, or security deposit, I was induced to transfer INR {amount_lost:,.2f} to UPI handle '{suspect_upi}' under Transaction Ref '{utr_number}'. Subsequently, no genuine employment or equipment was delivered, and further extortion/threats were communicated.

V. PRAYER / RELIEF SOUGHT:
1. Urgent freeze of the beneficiary bank account / UPI wallet linked to '{suspect_upi}'.
2. Trace IP address, SIM registration, and KYC records associated with phone '{suspect_phone}'.
3. Registration of FIR and recovery of defrauded funds under the statutory mandate of Cyber Crime Helpline 1930.

I affirm that the particulars stated above are true and correct to the best of my knowledge.
Date: {datetime.now().strftime("%d-%B-%Y")}
Complainant: {complainant_name}"""

    # 2. Bank Immediate Transaction Freeze Notice
    bank_freeze_notice = f"""URGENT: FRAUD DISPUTE & BENEFICIARY ACCOUNT FREEZE REQUEST
To,
The Nodal Officer / Fraud Risk Management Cell
Subject: Immediate Lien / Freeze Request for Fraudulent UPI Transaction (Ref: {utr_number})

Respected Sir/Madam,

I am writing to report an unauthorized / fraudulent transaction executed from my account:
- Date of Transaction: {incident_date}
- Disputed Amount: INR {amount_lost:,.2f}
- Transaction UTR / Ref No: {utr_number}
- Beneficiary UPI ID: {suspect_upi}
- Impersonated Recruiter: {suspect_company} ({suspect_phone})

I have formally lodged a cybercrime complaint on the National Cyber Crime Reporting Portal (Helpline 1930).
In accordance with RBI Master Directions on customer protection and limiting liability in unauthorized electronic banking transactions, I request you to:
1. Immediately flag this transaction and coordinate with the beneficiary bank/PSP to place a lien/freeze on the recipient account holding UTR {utr_number}.
2. Provide the Beneficiary Bank Name, IFSC code, and Account Number for statutory police escalation.

Thank you.
Complainant Name: {complainant_name}
Phone: {complainant_phone}"""

    return {
        "portal_draft": portal_draft.strip(),
        "bank_freeze_notice": bank_freeze_notice.strip(),
        "generated_at": datetime.utcnow().isoformat(),
        "amount_inr": amount_lost,
        "utr_number": utr_number,
        "emergency_steps": [
            "1. Call 1930 immediately to log an emergency cyber fraud ticket within the golden hour.",
            "2. Copy the Bank Freeze Notice above and email it to your bank's fraud support desk.",
            "3. Copy the Portal Draft and paste into the incident description at cybercrime.gov.in.",
            "4. Export and save PDF/screenshots of all WhatsApp chats, email headers, and UPI payment receipts."
        ]
    }
