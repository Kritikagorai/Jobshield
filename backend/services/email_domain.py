"""
email_domain.py
---------------
Analyzes email addresses and web domains for fraud indicators:
1. Free public email services used for enterprise recruitment (Gmail, Yahoo).
2. Suspicious / throwaway Top-Level Domains (.xyz, .top, .vip, .site).
3. Typosquatting and spoofed domain variants (e.g., tcs-hiring.online vs tcs.com).
"""

import re
from typing import Dict, Any, Optional

# Free webmail providers commonly abused in hiring scams
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in",
    "outlook.com", "hotmail.com", "rediffmail.com", "protonmail.com",
    "mail.com", "zoho.com", "icloud.com", "aol.com", "yandex.com"
}

# High-risk, cheap, or disposable top-level domains frequently used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".vip", ".club", ".site", ".online", ".live",
    ".buzz", ".icu", ".cc", ".work", ".link", ".info", ".biz", ".tk", ".ml"
}

# Major brand roots vulnerable to lookalike / typosquatting domains
KNOWN_ENTERPRISE_BRANDS = [
    "tcs", "infosys", "wipro", "hcl", "techmahindra", "tatamotors",
    "reliance", "jio", "amazon", "flipkart", "swiggy", "zomato",
    "google", "microsoft", "accenture", "cognizant", "capgemini",
    "icici", "hdfc", "axis", "sbi", "deloitte"
]


def extract_domain(email_or_url: str) -> str:
    """Extracts the clean domain name from an email address or URL string."""
    text = str(email_or_url).strip().lower()
    # Strip protocol if URL
    if "://" in text:
        text = text.split("://")[1]
    # Strip URL paths or query params
    text = text.split("/")[0].split("?")[0].split("#")[0]
    # If it is an email address, get the part after @
    if "@" in text:
        text = text.split("@")[-1]
    # Strip port number if any
    if ":" in text:
        text = text.split(":")[0]
    return text


def is_free_email(email_or_domain: str) -> bool:
    """Checks whether the domain belongs to a free public email provider (e.g. Gmail)."""
    domain = extract_domain(email_or_domain)
    return domain in FREE_EMAIL_PROVIDERS


def has_suspicious_tld(domain_str: str) -> bool:
    """Checks whether the domain ends with a high-risk or disposable top-level domain."""
    domain = extract_domain(domain_str)
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def detect_typosquatting(domain_str: str, claimed_brand: str = "") -> Dict[str, Any]:
    """
    Detects whether a domain is an impersonation or typosquatting attempt of a well-known brand.
    Examples: 'tcs-hiring-portal.online', 'infosys-directhr.co.in', 'amazon-task-review.vip'
    """
    domain = extract_domain(domain_str)
    if not domain or is_free_email(domain):
        return {"is_typosquat": False, "target_brand": None, "reason": "Not a spoofed domain"}

    # Exact matches for genuine domains are safe
    genuine_domains = {
        "tcs.com", "infosys.com", "wipro.com", "hcltech.com", "techmahindra.com",
        "amazon.in", "amazon.com", "flipkart.com", "google.com", "microsoft.com"
    }
    if domain in genuine_domains:
        return {"is_typosquat": False, "target_brand": None, "reason": "Official verified domain"}

    # Check for known brand roots inside domain with hyphens or buzzwords
    norm_domain = domain.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s").replace("@", "a")
    brands_to_check = list(KNOWN_ENTERPRISE_BRANDS)
    if claimed_brand:
        clean_cb = re.sub(r'[^a-zA-Z0-9]', '', claimed_brand.lower())
        for suffix in ["limited", "pvt", "ltd", "technologies", "services", "corporation"]:
            clean_cb = clean_cb.replace(suffix, "")
        if len(clean_cb) >= 3 and clean_cb not in brands_to_check:
            brands_to_check.append(clean_cb)

    for brand in brands_to_check:
        # If the domain contains the brand name plus extra hiring keywords or leetspeak substitutions
        is_in_domain = brand in domain or brand in norm_domain
        if is_in_domain and domain != f"{brand}.com" and domain != f"{brand}.in":
            # Indicators of spoofing: hyphens, words like 'career', 'job', 'hr', 'hire', 'portal', or character alterations
            hiring_keywords = ["career", "job", "hiring", "hr", "recruitment", "desk", "portal", "direct", "work"]
            has_keyword = any(kw in norm_domain for kw in hiring_keywords)
            has_suspicious_extension = has_suspicious_tld(domain)
            is_leetspeak = (brand in norm_domain) and (brand not in domain)

            if "-" in domain or has_keyword or has_suspicious_extension or is_leetspeak:
                return {
                    "is_typosquat": True,
                    "target_brand": brand.upper(),
                    "suspicious_domain": domain,
                    "reason": (
                        f"Spoofing / Typosquatting Detected: Domain '{domain}' mimics {brand.upper()} using deceptive keywords or character substitution."
                    )
                }

    return {"is_typosquat": False, "target_brand": None, "reason": "No brand spoofing detected"}


def analyze_domain(domain_or_email: str, claimed_brand: str = "") -> Dict[str, Any]:
    """
    Performs comprehensive fraud inspection on an email or domain:
    - Free email detection
    - Suspicious TLD check
    - Brand typosquatting check
    """
    domain = extract_domain(domain_or_email)
    free_email = is_free_email(domain)
    suspicious_tld = has_suspicious_tld(domain)
    typo_check = detect_typosquatting(domain, claimed_brand=claimed_brand)

    risk_score = 0
    reasons = []

    if free_email:
        risk_score += 40
        reasons.append("Sender uses a free public email provider (e.g., @gmail.com) instead of a corporate domain.")

    if suspicious_tld:
        risk_score += 35
        reasons.append(f"Domain uses a suspicious or throwaway extension ({domain[domain.rfind('.'):]}).")

    if typo_check.get("is_typosquat"):
        risk_score += 50
        reasons.append(typo_check["reason"])

    # Cap risk score at 100
    risk_score = min(risk_score, 100)

    return {
        "domain": domain,
        "is_free_email": free_email,
        "has_suspicious_tld": suspicious_tld,
        "is_typosquat": typo_check.get("is_typosquat", False),
        "target_brand": typo_check.get("target_brand"),
        "domain_risk_score": risk_score,
        "reasons": reasons
    }


def is_safe_url(url_string: str) -> Dict[str, Any]:
    """
    Evaluates URL security, checks HTTPS status, and implements SSRF protection.
    Blocks private IP addresses, loopback, and suspicious internal ports.
    """
    if not url_string:
        return {"is_safe": True, "reasons": ["No URL provided"], "is_https": False}

    import ipaddress
    import urllib.parse
    import socket

    clean_url = url_string.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    is_https = parsed.scheme == "https"

    reasons = []
    is_safe = True

    # 1. HTTPS Check
    if not is_https:
        reasons.append("Unsecured Connection: URL uses unencrypted HTTP instead of HTTPS.")

    # 2. Check for raw IP address as host
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return {
                "is_safe": False,
                "is_internal": True,
                "is_https": is_https,
                "hostname": hostname,
                "reasons": ["Blocked: Internal, private, or loopback network address detected (SSRF Protection)."]
            }
        reasons.append(f"Suspicious Host: Site uses a raw IP address ({hostname}) instead of a registered domain name.")
    except ValueError:
        pass

    # 3. DNS resolution SSRF check (if hostname is a domain name)
    if not is_ip and hostname:
        try:
            # Quick local resolution check with 1-second timeout
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return {
                    "is_safe": False,
                    "is_internal": True,
                    "is_https": is_https,
                    "hostname": hostname,
                    "reasons": ["Blocked: Domain resolves to an internal or private network address (SSRF Protection)."]
                }
        except (socket.gaierror, socket.timeout, Exception):
            # Gracefully ignore if offline or DNS cannot resolve
            pass

    # 4. Check for unusual ports
    if port and port not in [80, 443, 8080]:
        reasons.append(f"Suspicious Port: Connection uses non-standard web port {port}.")
        is_safe = False

    # 5. Check for excessive subdomains (e.g. tcs.hiring.portal.apply.scam.xyz)
    subdomains = hostname.split(".")
    if len(subdomains) > 4:
        reasons.append(f"Deceptive Subdomains: Multiple nested subdomains ({len(subdomains)}) commonly used in phishing.")

    # 6. Lookalike homoglyphs / punycode check
    if "xn--" in hostname:
        reasons.append("Punycode Detected: Internationalized domain name which may use homoglyphs to impersonate brands.")

    return {
        "is_safe": len(reasons) == 0,
        "is_https": is_https,
        "hostname": hostname,
        "is_ip": is_ip,
        "reasons": reasons if reasons else ["Connection uses standard HTTPS without obvious network anomalies."]
    }


def check_domain_registration_age(domain_str: str, timeout_sec: float = 2.0) -> Dict[str, Any]:
    """
    Safely inspects domain registration status using RDAP/DNS lookups with a strict timeout.
    Gracefully handles privacy protection and offline environments without false accusations.
    """
    domain = extract_domain(domain_str)
    if not domain or is_free_email(domain):
        return {
            "available": False,
            "status": "NOT_APPLICABLE",
            "message": "Domain age check not applicable for free public email services or empty domains."
        }

    import urllib.request
    import json
    import socket

    rdap_url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(
        rdap_url,
        headers={"User-Agent": "JobShield-SecurityAuditor/2.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                events = data.get("events", [])
                reg_date = None
                for ev in events:
                    if ev.get("eventAction") in ["registration", "created"]:
                        reg_date = ev.get("eventDate", "")[:10]
                        break

                if reg_date:
                    return {
                        "available": True,
                        "status": "VERIFIED_LOOKUP",
                        "registration_date": reg_date,
                        "message": f"Domain registered on: {reg_date}."
                    }
    except Exception:
        # Fallback to basic DNS check
        try:
            socket.gethostbyname(domain)
            return {
                "available": False,
                "status": "PRIVACY_OR_OFFLINE",
                "message": "Domain is active on DNS; detailed registration date is privacy-protected or lookup timed out."
            }
        except Exception:
            return {
                "available": False,
                "status": "UNAVAILABLE",
                "message": "Domain registration lookup unavailable (timeout or privacy protection). This is not proof of fraud."
            }

    return {
        "available": False,
        "status": "UNAVAILABLE",
        "message": "Registration details unavailable. This is treated as an unverified check, not evidence of malice."
    }


def verify_recruiter_domain_mismatch(
    email_or_domain: str,
    claimed_company: str = "",
    url: str = ""
) -> Dict[str, Any]:
    """
    Comprehensive Recruiter Email & Domain Mismatch Checker.
    Cross-checks the recruiter's contact domain against official corporate registries,
    detects typosquatting, lookalike subdomains, free email abuse, and URL security.
    """
    import database

    clean_email = (email_or_domain or "").strip().lower()
    clean_domain = extract_domain(clean_email or url)
    company_query = (claimed_company or "").strip()

    # 1. Base Domain Analysis
    dom_analysis = analyze_domain(clean_domain, claimed_brand=company_query)
    url_analysis = is_safe_url(url) if url else None
    free_email = is_free_email(clean_domain)

    # 2. Company Registry Cross-Reference
    matched_comp = database.db_manager.find_company(company_query) if company_query else None
    if not matched_comp and clean_domain:
        # Try matching by domain if company name wasn't explicitly provided
        matched_comp = database.db_manager.find_company(clean_domain)

    is_mismatch = False
    mismatch_severity = "NONE"
    warning_signs = []
    verified_findings = []
    unavailable_checks = []

    # 3. Email vs Company Verification
    if matched_comp:
        comp_name = matched_comp.get("name")
        official_domains = [d.lower() for d in matched_comp.get("official_email_domains", [])]
        official_web = (matched_comp.get("official_domain") or "").lower()
        if official_web and official_web not in official_domains:
            official_domains.append(official_web)

        if free_email:
            is_mismatch = True
            mismatch_severity = "CRITICAL"
            warning_signs.append(
                f"Corporate Mismatch: The recruiter claims to represent '{comp_name}', but is using a free public email (@{clean_domain}). "
                f"Official {comp_name} recruiters exclusively use corporate @{official_web or official_domains[0]} mailboxes."
            )
        elif clean_domain and official_domains and clean_domain not in official_domains:
            is_mismatch = True
            mismatch_severity = "HIGH"
            warning_signs.append(
                f"Domain Mismatch: Recruiter domain (@{clean_domain}) does not match the official registered domain(s) for {comp_name} ({', '.join(official_domains)})."
            )
        elif clean_domain in official_domains:
            verified_findings.append(
                f"Official Match: Recruiter domain (@{clean_domain}) matches official registered records for {comp_name}."
            )
    else:
        if company_query:
            unavailable_checks.append(
                f"Company '{company_query}' is not listed in the verified MCA registry baseline. Manual verification recommended."
            )
        if free_email:
            warning_signs.append(
                f"Free Webmail Used: Contact uses @{clean_domain}. Reputable employers generally use proprietary business domains."
            )

    # 4. Typosquatting & Lookalike Check
    if dom_analysis.get("is_typosquat"):
        is_mismatch = True
        mismatch_severity = "CRITICAL"
        warning_signs.append(dom_analysis["reasons"][0])

    if dom_analysis.get("has_suspicious_tld"):
        warning_signs.append(
            f"Disposable / Cheap TLD: Domain ends in a top-level extension frequently exploited for throwaway scam pages."
        )

    # 5. URL Safety Findings
    if url_analysis and not url_analysis.get("is_safe"):
        for reason in url_analysis.get("reasons", []):
            warning_signs.append(reason)
    elif url_analysis and url_analysis.get("is_https"):
        verified_findings.append("Secure Transport: Portal uses valid HTTPS protocol.")

    # 6. Domain Age Lookup
    age_check = check_domain_registration_age(clean_domain)
    if age_check.get("available") and age_check.get("registration_date"):
        verified_findings.append(f"Domain Registration: Officially registered on {age_check['registration_date']}.")
    else:
        unavailable_checks.append(age_check.get("message", "Domain registration age unavailable."))

    # 7. Recommendations
    recommendations = []
    if is_mismatch or mismatch_severity in ["CRITICAL", "HIGH"]:
        recommendations.append(f"Do NOT send money or submit identity documents to this recruiter.")
        recommendations.append(f"Visit the company's official careers site directly rather than using links in emails.")
        recommendations.append(f"Contact the company's verified switchboard or HR desk to verify the recruiter's name.")
    else:
        recommendations.append("Continue with standard precautions: never pay registration deposits or share banking OTPs.")

    url_safe = url_analysis.get("is_safe", True) if url_analysis else True
    url_check_note = "; ".join(url_analysis.get("reasons", [])) if url_analysis else ""
    warning_message = "; ".join(warning_signs) if warning_signs else ""

    return {
        "is_mismatch": is_mismatch,
        "mismatch_detected": is_mismatch,
        "mismatch_severity": mismatch_severity,
        "inspected_domain": clean_domain,
        "claimed_company": company_query or (matched_comp.get("name") if matched_comp else "Not Specified"),
        "is_known_company": bool(matched_comp),
        "official_domains": matched_comp.get("official_email_domains", []) if matched_comp else [],
        "is_free_email": free_email,
        "is_typosquat": dom_analysis.get("is_typosquat", False),
        "typosquatting_detected": dom_analysis.get("is_typosquat", False),
        "target_brand": dom_analysis.get("target_brand"),
        "url_safe": url_safe,
        "url_check_note": url_check_note,
        "url_safety": url_analysis,
        "registration_age_info": age_check,
        "warning_signs": warning_signs,
        "warning_message": warning_message,
        "verified_findings": verified_findings,
        "unavailable_checks": unavailable_checks,
        "recommendations": recommendations,
        "disclaimer": "Domain mismatch and email inspections provide threat indicators. A free email or private domain is a risk indicator, not definitive proof of fraud."
    }
