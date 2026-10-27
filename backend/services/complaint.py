"""
complaint.py
------------
Generates formal, ready-to-file legal complaint drafts for:
1. National Cyber Crime Reporting Portal (cybercrime.gov.in)
2. National Cyber Financial Fraud Helpline (1930)
3. Immediate Bank Account & UPI Freeze Request Letters

Legal references updated to Bharatiya Nyaya Sanhita (BNS), 2023
and Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 — effective 1 July 2024.
"""

from datetime import datetime, timezone
from typing import Dict, Any


def generate_cybercrime_complaint(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a complete complaint package:
    - Formal cybercrime portal narrative (cybercrime.gov.in)
    - Bank UPI freeze letter (with RBI citation and NPCI recall steps)
    - DoT Chakshu / Sanchar Saathi phone block step
    - Action checklist for golden-hour response
    - Applicable BNS 2023 + IT Act legal sections
    """
    today_str = datetime.now().strftime("%d-%b-%Y")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Complainant
    complainant_name = (data.get("complainant_name") or "").strip() or "[Victim / Applicant Full Name]"
    complainant_phone = (data.get("complainant_phone") or "").strip() or "[Your Mobile Number]"
    complainant_city = (data.get("complainant_city") or "").strip() or "[Your City / State]"

    # Suspect
    suspect_name = (data.get("suspect_name") or "").strip() or "Unknown / Unidentified Fraudster"
    suspect_phone = (data.get("suspect_phone") or "").strip() or "Not Provided"
    suspect_email = (data.get("suspect_email") or "").strip() or "Not Provided"
    suspect_upi = (data.get("suspect_upi") or "").strip() or "Not Provided"
    suspect_company = (data.get("suspect_company") or "").strip() or "Unverified Impersonator Entity"

    # Incident
    amount_lost = float(data.get("amount_lost") or 0.0)
    utr_number = (data.get("utr_number") or "").strip() or "[12-digit Bank Transaction / UTR Number]"
    incident_date = (data.get("incident_date") or "").strip() or today_str
    scam_category = (data.get("scam_category") or "").strip() or "Employment / Fake Job Offer Scam"
    narrative = (data.get("narrative") or "").strip() or "The suspect contacted me offering employment and demanded upfront payments under false pretenses."

    # Formatted amount
    amount_str = f"INR {amount_lost:,.2f}" if amount_lost > 0 else "[Amount to be confirmed from bank statement]"

    # ---------------------------------------------------------------------------
    # DOCUMENT 1: National Cybercrime Portal Complaint Text
    # ---------------------------------------------------------------------------
    portal_text = f"""FORMAL COMPLAINT UNDER THE INFORMATION TECHNOLOGY ACT, 2000
AND BHARATIYA NYAYA SANHITA (BNS), 2023

To:
The Station House Officer / Nodal Cyber Crime Officer
National Cyber Crime Reporting Portal — cybercrime.gov.in

Date of Complaint    : {today_str}
Complaint Category   : Online Financial Fraud — Fake Employment / Job Offer Scam

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION I — COMPLAINANT PARTICULARS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full Name           : {complainant_name}
Contact Number      : {complainant_phone}
City / State        : {complainant_city}
Date of Incident    : {incident_date}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION II — SUSPECT / ACCUSED IDENTIFIERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Suspect / Alias      : {suspect_name}
Company Impersonated : {suspect_company}
Suspect Phone / WA   : {suspect_phone}
Suspect Email        : {suspect_email}
Beneficiary UPI ID   : {suspect_upi}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION III — FINANCIAL LOSS & TRANSACTION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Amount Defrauded : {amount_str}
Transaction UTR / Ref  : {utr_number}
Mode of Transfer       : UPI / Digital Wallet
Beneficiary UPI Handle : {suspect_upi}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION IV — STATEMENT OF FACTS (INCIDENT NARRATIVE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Category of Fraud: {scam_category}

On or around {incident_date}, I, {complainant_name}, was targeted by fraudsters
claiming to represent "{suspect_company}". The accused made contact via
{suspect_phone} and/or email {suspect_email}.

Detailed Account of Events:
{narrative}

Under false pretense of employment onboarding / equipment dispatch / security
deposit, I was fraudulently induced to transfer {amount_str} to UPI ID
'{suspect_upi}' (Transaction Ref: {utr_number}). No genuine employment,
equipment, or refund was subsequently provided. Further communications were
blocked by the accused.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION V — APPLICABLE LEGAL PROVISIONS (BNS 2023 + IT ACT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bharatiya Nyaya Sanhita (BNS), 2023 — Effective 1 July 2024:
  • Section 318 BNS — Cheating [replaces IPC Section 420]
  • Section 319 BNS — Cheating by personation [replaces IPC Section 419]
  • Section 336 BNS — Forgery for fraud [replaces IPC Section 468]
  • Section 351(4) BNS — Criminal intimidation [replaces IPC Section 506]

Information Technology Act, 2000:
  • Section 66C — Punishment for identity theft
  • Section 66D — Cheating by personation via computer resource

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION VI — PRAYER / RELIEF SOUGHT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Register this complaint and assign a Complaint / FIR number.
2. Immediately freeze UPI ID '{suspect_upi}' and linked bank account
   before funds are transferred or withdrawn.
3. Trace SIM card registration, IMEI, and KYC records linked to
   phone number '{suspect_phone}'.
4. Initiate NPCI / RBI inter-bank coordination for fund recall
   under Transaction UTR: {utr_number}.
5. Coordinate with ISP / Meta / Google to preserve digital evidence
   associated with email '{suspect_email}'.

Declaration: I hereby affirm that all particulars stated above are true
and correct to the best of my knowledge and belief.

Date: {today_str}
Complainant: {complainant_name}
Contact    : {complainant_phone} | {complainant_city}

[Attach: WhatsApp/Telegram chat exports, payment receipt screenshot, offer letter PDF]"""

    # ---------------------------------------------------------------------------
    # DOCUMENT 2: Urgent Bank UPI Freeze Letter
    # ---------------------------------------------------------------------------
    bank_letter = f"""URGENT — FRAUD DISPUTE & BENEFICIARY ACCOUNT FREEZE REQUEST
Date: {today_str}

To,
The Nodal Officer / Cyber Fraud Risk Management Cell
[Your Bank Name — e.g. SBI / HDFC / ICICI / Axis / Kotak]
[Branch Address]

Subject: Immediate Request for Transaction Recall & Lien on Fraudulent
         Beneficiary UPI ID — Transaction Ref: {utr_number}

Respected Sir / Madam,

I, {complainant_name} (Mobile: {complainant_phone}), am writing to urgently
report a fraudulent transaction and request immediate inter-bank lien
placement under RBI Master Directions on Limiting the Liability of Customers
in Unauthorized Electronic Banking Transactions (RBI/DPSS/2017-18/58).

── TRANSACTION DETAILS ──────────────────────────────────────────
Date of Disputed Transaction : {incident_date}
Amount Deducted              : {amount_str}
Transaction Reference (UTR)  : {utr_number}
Beneficiary UPI ID / VPA     : {suspect_upi}
Fraudster Phone / WhatsApp   : {suspect_phone}
Fraudster Email              : {suspect_email}
Impersonated Entity          : {suspect_company}
─────────────────────────────────────────────────────────────────

FACTS OF THE CASE:
I was deceived by individuals impersonating "{suspect_company}" via
{suspect_phone} and {suspect_email} into transferring {amount_str}
under the false pretext of an employment security deposit or equipment
courier fee. This transaction was made under fraudulent misrepresentation.

ACTION REQUESTED:
1. Immediately place a LIEN / FLAG on the beneficiary account linked
   to UPI ID '{suspect_upi}' to prevent fund withdrawal or laundering.
2. Initiate an inter-bank CHARGEBACK / TRANSACTION RECALL via the NPCI
   Dispute Portal using Transaction Reference: {utr_number}.
3. Share the Beneficiary Bank Name, IFSC Code, and Account Number for
   police escalation and potential court-ordered attachment proceedings.
4. Issue a Transaction Hold Certificate acknowledging this complaint
   for submission as evidence to the Cyber Crime Police Station.

I have already reported this incident on:
  • National Cyber Crime Helpline (1930) — Complaint ID: [To be obtained]
  • National Cyber Crime Portal: https://cybercrime.gov.in
  • DoT Sanchar Saathi (Chakshu): https://sancharsaathi.gov.in

Thank you for your urgent assistance.

Yours faithfully,
Name     : {complainant_name}
Phone    : {complainant_phone}
City     : {complainant_city}
Date     : {today_str}

[Attach: Bank statement showing UTR {utr_number}, scam communication screenshots]"""

    # ---------------------------------------------------------------------------
    # Action Checklist (time-ordered, golden-hour priority)
    # ---------------------------------------------------------------------------
    checklist = [
        "🚨 STEP 1 (IMMEDIATE ≤ 2 HRS): Call 1930 (National Cyber Helpline). Provide UTR number, bank name, and suspect UPI ID to trigger an emergency account freeze.",
        "🏦 STEP 2 (≤ 2 HRS): Email the Bank Freeze Letter to your bank's Nodal Cyber Fraud Officer with UTR reference. Find the email at your bank's website under 'Report Fraud'.",
        "🖥️ STEP 3 (SAME DAY): File on https://cybercrime.gov.in → 'Report Cyber Crime' → 'Financial Fraud' → 'Job / Employment Fraud'. Paste the Portal Complaint draft.",
        "📱 STEP 4: Report scammer's phone at https://sancharsaathi.gov.in/sfc/ (DoT Chakshu) to get the SIM card blocked across all telecom operators.",
        "📋 STEP 5: Preserve ALL evidence — export full WhatsApp/Telegram chats as .txt, screenshot payment screens and offer letter. Do NOT block or delete the suspect yet.",
        "🏛️ STEP 6 (if amount > ₹10,000): File a Zero FIR at your nearest police station Cyber Cell with the Cybercrime portal complaint acknowledgment number.",
    ]

    # Applicable legal sections (BNS 2023 + IT Act)
    legal_sections = [
        "BNS Section 318 (2023) — Cheating [replaces IPC Section 420]",
        "BNS Section 319 (2023) — Cheating by personation [replaces IPC Section 419]",
        "BNS Section 336 (2023) — Forgery for fraud [replaces IPC Section 468]",
        "BNS Section 351(4) (2023) — Criminal intimidation [replaces IPC Section 506]",
        "IT Act Section 66C — Identity theft using computer resource",
        "IT Act Section 66D — Cheating by personation via computer resource",
    ]

    # Email subject helpers
    subject_portal = f"Cyber Fraud Complaint — Job Scam — {scam_category} — {today_str}"
    subject_bank = f"URGENT: Fraud Transaction Recall — UTR {utr_number} — Beneficiary UPI {suspect_upi}"

    return {
        # Primary keys consumed by frontend (both aliases kept for compatibility)
        "portal_draft": portal_text.strip(),
        "portal_complaint_text": portal_text.strip(),
        "bank_freeze_notice": bank_letter.strip(),
        "bank_freeze_letter": bank_letter.strip(),

        # Rich metadata
        "applicable_legal_sections": legal_sections,
        "action_checklist": checklist,
        "helpline_numbers": {
            "national_cyber_helpline": "1930",
            "emergency_police": "112",
            "official_portal": "https://cybercrime.gov.in",
            "dot_chakshu": "https://sancharsaathi.gov.in/sfc/",
            "rbi_ombudsman": "https://cms.rbi.org.in",
        },

        # Utility fields for UI download / display helpers
        "generated_at": now_iso,
        "incident_date": incident_date,
        "amount_inr": amount_lost,
        "utr_number": utr_number,
        "subject_portal": subject_portal,
        "subject_bank": subject_bank,
        "complainant_name": complainant_name,
    }
