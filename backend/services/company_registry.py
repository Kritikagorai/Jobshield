"""
company_registry.py
-------------------
Looks up company credentials against the verified enterprise registry.
Detects corporate impersonation by cross-verifying claimed names, CIN,
GSTIN, and sender email domains against official records.
"""

from typing import Dict, Any, Optional, List
import database


def find_company_in_registry(query: str) -> Optional[Dict[str, Any]]:
    """
    Searches the company registry by company name, alias, CIN, or official domain.
    Returns the company profile if found, or None if unlisted.
    """
    if not query:
        return None
    return database.db_manager.find_company(query)


def get_all_registered_companies() -> List[Dict[str, Any]]:
    """Returns the list of all registered companies (genuine, flagged, unverified)."""
    return database.db_manager.get_all_companies()


def verify_company_credentials(
    claimed_name: Optional[str] = None,
    provided_cin: Optional[str] = None,
    provided_gstin: Optional[str] = None,
    sender_domain: Optional[str] = None,
    sender_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cross-verifies claimed company details against official registry records.
    Catches impersonation attacks where scammers forge a legitimate company's name
    but use a fake domain, unofficial email, or mismatched CIN.
    """
    # 1. Search registry by name, domain, or CIN
    matched_company = None
    if claimed_name:
        matched_company = find_company_in_registry(claimed_name)
    if not matched_company and provided_cin:
        matched_company = find_company_in_registry(provided_cin)
    if not matched_company and sender_domain:
        matched_company = find_company_in_registry(sender_domain)

    # If company is not found in database registry
    if not matched_company:
        return {
            "found_in_registry": False,
            "status": "UNVERIFIED",
            "company_name": claimed_name or "Unknown Entity",
            "is_impersonation": False,
            "recruitment_policy": "Company not found in JobShield registry. Exercise caution and verify independently.",
            "discrepancies": ["Company name is not listed in JobShield verified corporate registry."]
        }

    discrepancies = []
    is_impersonation = False

    # Extract official domains from matched record
    official_domain = matched_company.get("official_domain", "").lower()
    official_email_domains = [
        d.lower() for d in matched_company.get("official_email_domains", [])
    ]
    if official_domain and official_domain not in official_email_domains:
        official_email_domains.append(official_domain)

    # 2. Check sender domain / email match
    if sender_domain:
        s_domain = sender_domain.lower()
        if official_email_domains and s_domain not in official_email_domains:
            is_impersonation = True
            discrepancies.append(
                f"Domain Mismatch: Claimed company uses '@{official_domain}', but email domain is '{s_domain}'."
            )

    if sender_email:
        email_clean = sender_email.lower()
        domain_part = email_clean.split("@")[-1] if "@" in email_clean else ""
        if domain_part in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"]:
            is_impersonation = True
            discrepancies.append(
                f"Free Email Impersonation: Major corporation '{matched_company['name']}' never sends offers from free public email providers (@{domain_part})."
            )

    # 3. Check CIN match
    official_cin = matched_company.get("cin", "").upper()
    if provided_cin and official_cin:
        if provided_cin.upper() != official_cin:
            is_impersonation = True
            discrepancies.append(
                f"CIN Hijacking: Provided CIN '{provided_cin}' does not match official CIN '{official_cin}'."
            )

    # 4. Check GSTIN match
    official_gstin = matched_company.get("gstin", "").upper()
    if provided_gstin and official_gstin:
        if provided_gstin.upper() != official_gstin:
            discrepancies.append(
                f"GSTIN Mismatch: Provided GSTIN '{provided_gstin}' does not match official GSTIN '{official_gstin}'."
            )

    # Determine status
    is_genuine_flag = matched_company.get("is_genuine", True)
    if not is_genuine_flag:
        status = "FLAGGED_FAKE"
        discrepancies.append("Warning: This organization is already flagged in the community scam database.")
    elif is_impersonation:
        status = "SUSPECTED_IMPERSONATION"
    else:
        status = "VERIFIED_GENUINE"

    return {
        "found_in_registry": True,
        "company_name": matched_company.get("name", claimed_name),
        "status": status,
        "is_impersonation": is_impersonation,
        "official_domain": official_domain,
        "official_cin": official_cin,
        "official_gstin": official_gstin,
        "registered_address": matched_company.get("registered_address", ""),
        "recruitment_policy": matched_company.get(
            "recruitment_policy",
            "This company maintains a zero-fee recruitment policy."
        ),
        "discrepancies": discrepancies
    }
