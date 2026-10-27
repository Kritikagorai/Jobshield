"""
validators.py
-------------
Validates Indian corporate identifiers (CIN, GSTIN, and PAN) using
official Ministry of Corporate Affairs (MCA) formats, state codes,
and the Goods and Services Tax (GST) Mod-36 checksum algorithm.
"""

import re
from typing import Dict, Any

# Valid 2-letter state codes for Indian CIN registrations
VALID_INDIAN_STATES = {
    "AP", "AR", "AS", "BR", "CG", "CH", "DD", "DL", "DN", "GA",
    "GJ", "HR", "HP", "JH", "JK", "KA", "KL", "LA", "LD", "MH",
    "ML", "MN", "MP", "MZ", "NL", "OD", "PB", "PY", "RJ", "SK",
    "TN", "TR", "TS", "UK", "UP", "WB"
}

# Recognized MCA company type codes
MCA_COMPANY_TYPES = {
    "PLC": "Public Limited Company",
    "PTC": "Private Limited Company",
    "LLP": "Limited Liability Partnership",
    "GOI": "Government of India Enterprise",
    "SGC": "State Government Company",
    "FLC": "Financial Lease Company",
    "ULL": "Unlimited Liability Company",
    "NPL": "Non-Profit License Company (Section 8)"
}


def validate_cin(cin: str) -> Dict[str, Any]:
    """
    Validates a 21-character Indian Corporate Identification Number (CIN).
    Example: L22210MH1995PLC084781
    Format: [L/U][5 digits][2-letter state][4-digit year][3-letter type][6-digit reg]
    """
    if not cin:
        return {"valid": False, "reason": "CIN is empty or not provided"}

    clean_cin = cin.strip().upper()
    if len(clean_cin) != 21:
        return {
            "valid": False,
            "reason": f"Invalid length: CIN must be exactly 21 characters (got {len(clean_cin)})"
        }

    pattern = r'^([LU])(\d{5})([A-Z]{2})(\d{4})([A-Z]{3})(\d{6})$'
    match = re.match(pattern, clean_cin)
    if not match:
        return {
            "valid": False,
            "reason": "CIN format does not follow MCA alphanumeric rules"
        }

    listing, industry_code, state_code, year, comp_type, reg_num = match.groups()

    # Validate state code
    if state_code not in VALID_INDIAN_STATES:
        return {
            "valid": False,
            "reason": f"Unknown Indian state code '{state_code}' in CIN"
        }

    # Validate incorporation year
    incorporation_year = int(year)
    if incorporation_year < 1850 or incorporation_year > 2026:
        return {
            "valid": False,
            "reason": f"Unrealistic incorporation year {incorporation_year} in CIN"
        }

    return {
        "valid": True,
        "cin": clean_cin,
        "is_listed": listing == "L",
        "listing_status": "Stock Exchange Listed" if listing == "L" else "Unlisted / Private",
        "industry_nic_code": industry_code,
        "state": state_code,
        "incorporation_year": incorporation_year,
        "company_type_code": comp_type,
        "company_type_name": MCA_COMPANY_TYPES.get(comp_type, "Registered Company"),
        "registration_number": reg_num,
        "reason": "CIN format and state code are structurally valid under MCA guidelines"
    }


def compute_gstin_checksum(gstin_14: str) -> str:
    """
    Computes the official GSTIN 15th character checksum using the Mod-36 Luhn formula.
    Chars 0-9 have values 0-9; chars A-Z have values 10-35.
    """
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    char_map = {c: i for i, c in enumerate(chars)}

    factor = 1
    total = 0

    for ch in reversed(gstin_14.upper()):
        val = char_map.get(ch, 0)
        product = val * factor
        # Quotient and remainder in base 36
        quotient = product // 36
        remainder = product % 36
        total += quotient + remainder
        factor = 2 if factor == 1 else 1

    check_digit = (36 - (total % 36)) % 36
    return chars[check_digit]


def validate_gstin(gstin: str) -> Dict[str, Any]:
    """
    Validates a 15-character Indian Goods and Services Tax Identification Number (GSTIN).
    Example: 27AAACT2828Q1ZP
    Format: [2 state digits][10 PAN chars][1 entity digit][Z][1 checksum char]
    """
    if not gstin:
        return {"valid": False, "reason": "GSTIN is empty or not provided"}

    clean_gstin = gstin.strip().upper()
    if len(clean_gstin) != 15:
        return {
            "valid": False,
            "reason": f"GSTIN must be exactly 15 characters (got {len(clean_gstin)})"
        }

    pattern = r'^(\d{2})([A-Z]{5}\d{4}[A-Z]{1})([1-9A-Z]{1})(Z)([0-9A-Z]{1})$'
    match = re.match(pattern, clean_gstin)
    if not match:
        return {
            "valid": False,
            "reason": "GSTIN format is invalid (14th char must be 'Z' and chars 3-12 must be a valid PAN)"
        }

    state_code, pan, entity_number, z_char, provided_checksum = match.groups()
    state_num = int(state_code)
    # Valid Indian GST state codes are 01-38, 97 (Other Territory), 99 (Center)
    if not (1 <= state_num <= 38 or state_num in [97, 99]):
        return {
            "valid": False,
            "reason": f"State code '{state_code}' is outside valid Indian GST jurisdictions"
        }

    # Verify checksum
    expected_checksum = compute_gstin_checksum(clean_gstin[:14])
    checksum_valid = (provided_checksum == expected_checksum)

    return {
        "valid": True,
        "gstin": clean_gstin,
        "state_code": state_code,
        "pan": pan,
        "entity_number": entity_number,
        "checksum_valid": checksum_valid,
        "expected_checksum": expected_checksum,
        "reason": (
            "Valid GSTIN with verified Mod-36 checksum" if checksum_valid
            else f"GSTIN structure valid but checksum mismatch (expected '{expected_checksum}', got '{provided_checksum}')"
        )
    }


def validate_pan(pan: str) -> Dict[str, Any]:
    """
    Validates a 10-character Indian Permanent Account Number (PAN).
    Example: AAACT2828Q
    Format: [5 uppercase letters][4 digits][1 uppercase letter]
    The 4th letter identifies the legal entity type (C = Company, P = Individual, etc.).
    """
    if not pan:
        return {"valid": False, "reason": "PAN is empty or not provided"}

    clean_pan = pan.strip().upper()
    pattern = r'^([A-Z]{3})([CPHFATBLJG])([A-Z])(\d{4})([A-Z])$'
    match = re.match(pattern, clean_pan)
    if not match:
        return {
            "valid": False,
            "reason": "PAN must follow 5 letters, 4 digits, 1 letter format with standard entity designation"
        }

    entity_types = {
        "C": "Company / Corporation",
        "P": "Individual / Person",
        "H": "Hindu Undivided Family (HUF)",
        "F": "Partnership Firm",
        "A": "Association of Persons (AOP)",
        "T": "Trust",
        "B": "Body of Individuals (BOI)",
        "L": "Local Authority",
        "J": "Artificial Juridical Person",
        "G": "Government Agency"
    }

    entity_code = match.group(2)
    return {
        "valid": True,
        "pan": clean_pan,
        "entity_type_code": entity_code,
        "entity_type_name": entity_types.get(entity_code, "Registered Entity"),
        "is_corporate_pan": entity_code in ["C", "F", "A", "T", "G"],
        "reason": f"Valid PAN assigned to {entity_types.get(entity_code, 'Entity')}"
    }
