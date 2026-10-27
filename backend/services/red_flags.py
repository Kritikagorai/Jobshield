"""
red_flags.py
------------
Deterministic rule-based scanner that identifies scam indicators:
1. Upfront monetary demands (courier deposit, uniform fee, registration charge).
2. Identity theft attempts (blank cancelled cheque, Aadhaar OTP, netbanking).
3. Telegram / WhatsApp task-scam redirection patterns.
4. Legal extortion and threat intimidation (IPC 420, breach penalties).
5. Direct offers without formal interview assessments.
"""

import re
from typing import Dict, List, Any

# Pattern dictionaries for each fraud category
RED_FLAG_PATTERNS = {
    "PAYMENT_DEMAND": {
        "severity": "CRITICAL",
        "title": "Upfront Money Demand",
        "description": "Genuine employers NEVER ask candidates to pay money for equipment, registration, uniforms, or training.",
        "regex": r'(?:refundable|security|courier|uniform|gate pass|badge|laptop|training|registration|processing|documentation|insurance)\s*(?:fee|deposit|charge|amount|cost|challan)|pay\s*(?:via|through)?\s*(?:gpay|phonepe|paytm|upi|google pay)|transfer\s*(?:rs|inr|\u20b9)\s*\d+'
    },
    "PERSONAL_DATA_THEFT": {
        "severity": "CRITICAL",
        "title": "Sensitive Document Extortion",
        "description": "Requesting blank cheques, bank passwords, or OTPs puts candidate bank accounts and identity at immediate risk.",
        "regex": r'cancelled cheque|bank passbook photo|atm pin|net banking|send otp|share otp|blank cheque|debit card cvv|original certificate deposit'
    },
    "TASK_SCAM": {
        "severity": "CRITICAL",
        "title": "Part-Time Task / Rating Scam",
        "description": "Schemes asking to like YouTube videos, boost hotel ratings, or recharge wallets are classic prepaid task frauds.",
        "regex": r'like\s*(?:\d+)?\s*youtube\s*video|product\s*rating|merchant\s*order|recharge\s*(?:your)?\s*wallet|daily\s*income\s*(?:rs|inr|\u20b9)\s*[1-9]\d{3,}|vip\s*task|earn\s*(?:rs|inr|\u20b9)\s*\d+\s*(?:daily|per day)'
    },
    "TELEGRAM_WHATSAPP_REDIRECT": {
        "severity": "HIGH",
        "title": "Informal Channel Redirection",
        "description": "Directing candidates away from corporate ATS portals to Telegram channels or private WhatsApp handles.",
        "regex": r'(?:telegram|t\.me/|(?:^|\s)@[\w_]{4,}(?:\s|$)|(?:contact|reach|connect|message|ping|text|call)\s*(?:us|me|hr)?\s*(?:on|at|via|through)?\s*whatsapp|whatsapp\s*(?:number|no|group|channel|helpline)|reception\s*manager\s*telegram)'
    },
    "LEGAL_INTIMIDATION": {
        "severity": "CRITICAL",
        "title": "Legal Threats & Extortion",
        "description": "Scammers invoke Section 420 IPC, court warrants, or heavy breach penalties to frighten victims into paying.",
        "regex": r'section\s*420|ipc\s*section|court\s*summons|legal\s*(?:notice|action|breach)|police\s*complaint|penalty\s*of\s*(?:rs|inr|\u20b9)|arrest\s*warrant'
    },
    "NO_INTERVIEW_DIRECT_OFFER": {
        "severity": "HIGH",
        "title": "Direct Offer Without Interview",
        "description": "Reputable companies never issue formal appointment orders without verified screening and interview rounds.",
        "regex": r'without\s*(?:any\s*)?(?:interview|test|exam)|direct\s*(?:selection|appointment|shortlist|quota)|profile\s*ranking\s*selection'
    },
    "SUSPICIOUS_WFH_INCOME": {
        "severity": "MEDIUM",
        "title": "Suspicious Work-From-Home Income Promise",
        "description": "Part-time home-based jobs promising unrealistic fixed income without experience or qualifications are common fraud vectors.",
        "regex": r'(?:work\s*from\s*home|wfh|home\s*based).*?(?:\d{2,3}00|\d{2,3},000)\s*(?:per\s*month|per\s*day|daily|monthly)|(?:no\s*experience|freshers?\s*(?:can\s*)?apply|no\s*qualification).*?(?:earn|income|salary|payment)\s*(?:rs|inr|\u20b9)?\s*\d{4,}'
    }
}


def scan_red_flags(text: str) -> Dict[str, Any]:
    """
    Scans a job offer or message text against all red flag rules.
    Returns matched categories, severity levels, and matching text snippets.
    """
    if not text:
        return {
            "has_red_flags": False,
            "flags": [],
            "critical_count": 0,
            "high_count": 0,
            "has_payment_demand": False,
            "has_data_theft": False
        }

    flags_found = []
    has_payment = False
    has_data_theft = False

    for category, meta in RED_FLAG_PATTERNS.items():
        pattern = meta["regex"]
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        if matches:
            # Capture the first 2 distinct snippets for evidence
            evidence_snippets = list(set([m.strip() for m in matches if m.strip()]))[:2]

            if category == "PAYMENT_DEMAND":
                has_payment = True
            if category == "PERSONAL_DATA_THEFT":
                has_data_theft = True

            flags_found.append({
                "category": category,
                "severity": meta["severity"],
                "title": meta["title"],
                "description": meta["description"],
                "matched_count": len(matches),
                "evidence_samples": evidence_snippets
            })

    critical_count = sum(1 for f in flags_found if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in flags_found if f["severity"] == "HIGH")

    return {
        "has_red_flags": len(flags_found) > 0,
        "flags": flags_found,
        "total_flags": len(flags_found),
        "critical_count": critical_count,
        "high_count": high_count,
        "has_payment_demand": has_payment,
        "has_data_theft": has_data_theft
    }
