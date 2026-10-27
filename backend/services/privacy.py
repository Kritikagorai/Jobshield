"""
privacy.py
----------
Protects candidate and victim privacy by masking sensitive personally
identifiable information (PII) including Aadhaar numbers, PAN cards,
phone numbers, and email addresses before displaying or saving data.
"""

import re
from typing import Dict, Any


def mask_aadhaar(text: str) -> str:
    """Masks 12-digit Indian Aadhaar numbers, showing only the last 4 digits (e.g. XXXX-XXXX-1234)."""
    # Matches 12-digit numbers with optional spaces or hyphens
    pattern = r'\b(\d{4})[\s\-]?(\d{4})[\s\-]?(\d{4})\b'
    return re.sub(pattern, r'XXXX-XXXX-\3', text)


def mask_pan(text: str) -> str:
    """Masks 10-character PAN cards, keeping only the last 4 characters visible (e.g. XXXXX1234F)."""
    pattern = r'\b([A-Z]{5})(\d{4}[A-Z])\b'
    return re.sub(pattern, r'XXXXX\2', text, flags=re.IGNORECASE)


def mask_phone(text: str) -> str:
    """Masks 10-digit Indian mobile numbers, keeping the first 2 and last 2 digits visible."""
    # Matches +91 or 0 prefix followed by 10 digits
    pattern = r'(\+?91[\s\-]?)?([6-9]\d{1})\d{6}(\d{2})\b'
    return re.sub(pattern, r'\1\2******\3', text)


def mask_email(text: str) -> str:
    """Masks personal email usernames (e.g., rahul.sharma@gmail.com -> r***a@gmail.com)."""
    def _mask_single_email(match):
        user = match.group(1)
        domain = match.group(2)
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + "***" + user[-1]
        return f"{masked_user}@{domain}"

    pattern = r'\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b'
    return re.sub(pattern, _mask_single_email, text)


def mask_sensitive_text(text: str) -> str:
    """Applies all PII masking filters (Aadhaar, PAN, phone, email) to a raw text string."""
    if not text:
        return ""
    result = mask_aadhaar(text)
    result = mask_pan(result)
    result = mask_phone(result)
    result = mask_email(result)
    return result


def mask_entity_dict(entities: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a copy of an entity dictionary with all sensitive personal values masked."""
    masked = dict(entities)
    if "pan" in masked and masked["pan"]:
        masked["pan"] = mask_pan(masked["pan"])
    if "phones" in masked and isinstance(masked["phones"], list):
        masked["phones"] = [mask_phone(p) for p in masked["phones"]]
    if "emails" in masked and isinstance(masked["emails"], list):
        masked["emails"] = [mask_email(e) for e in masked["emails"]]
    return masked
