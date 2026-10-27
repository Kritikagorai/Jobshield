"""
Entity Extractor Service for JobShield.
Performs deterministic and heuristic extraction of Indian employment credentials:
- Corporate Identification Number (CIN)
- Goods and Services Tax Identification Number (GSTIN)
- Permanent Account Number (PAN)
- Recruiter Phone Numbers & WhatsApp Links
- Recruiter Email Addresses (categorized as Free vs Official Domain)
- Unified Payments Interface (UPI) IDs / VPAs
- Telegram & WhatsApp Handles
- Salary Figures (LPA, Monthly, Stipends)
- Demanded Fees & Security Deposits
- Threat & Urgency Phrases (IPC 420, Blacklist, 2-hour limits)
- Multi-format file text extractor (.txt, .pdf, .docx, images)
"""
import re
import io
from typing import Dict, List, Any, Optional

# Free public email domains commonly abused by scam recruiters
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in",
    "hotmail.com", "outlook.com", "rediffmail.com", "protonmail.com",
    "mail.com", "zoho.com", "icloud.com", "aol.com", "yandex.com"
}

# Suspicious Top-Level Domains (TLDs) frequently used for throwaway phishing portals
SUSPICIOUS_TLDS = {".xyz", ".top", ".live", ".site", ".online", ".cc", ".buzz", ".vip", ".club", ".work"}

# Known genuine corporate email domains for major Indian employers
KNOWN_CORP_DOMAINS = {
    "tcs.com", "infosys.com", "wipro.com", "hcltech.com", "techmahindra.com",
    "cognizant.com", "accenture.com", "capgemini.com", "lntinfotech.com",
    "amazon.com", "google.com", "microsoft.com", "ibm.com", "deloitte.com"
}


def extract_cin(text: str) -> Optional[str]:
    """
    Extracts Indian 21-character Corporate Identification Number (CIN).
    Format: [L/U][5 digits][2-letter state][4-digit year][PLC/PTC/etc. 3 letters][6 digits]
    Example: L22210MH1995PLC084781
    """
    pattern = r'\b([LU][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6})\b'
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).upper() if match else None


def validate_cin_structure(cin: str) -> Dict[str, Any]:
    """Validates structural components of an Indian CIN."""
    if not cin:
        return {"valid": False, "reason": "No CIN provided"}
    
    clean_cin = cin.strip().upper()
    if len(clean_cin) != 21:
        return {"valid": False, "reason": f"CIN length is {len(clean_cin)}, expected 21 characters"}

    pattern = r'^([LU])([0-9]{5})([A-Z]{2})([0-9]{4})([A-Z]{3})([0-9]{6})$'
    match = re.match(pattern, clean_cin)
    if not match:
        return {"valid": False, "reason": "CIN does not match MCA alphanumeric structure"}

    listing, industry, state, year, comp_type, reg_num = match.groups()
    return {
        "valid": True,
        "listing": "Listed" if listing == "L" else "Unlisted",
        "industry_code": industry,
        "state": state,
        "incorporation_year": int(year),
        "company_type": comp_type,
        "registration_number": reg_num
    }


def extract_gstin(text: str) -> Optional[str]:
    """
    Extracts 15-character Indian Goods and Services Tax Identification Number (GSTIN).
    Format: [2 state digits][10 PAN chars][1 entity digit][Z][1 checksum char]
    Example: 27AAACT2828Q1ZP
    """
    pattern = r'\b([0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1})\b'
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).upper() if match else None


def extract_pan(text: str) -> Optional[str]:
    """
    Extracts 10-character Permanent Account Number (PAN).
    Format: [5 letters][4 digits][1 letter]
    """
    pattern = r'\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b'
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).upper() if match else None


def extract_phone_numbers(text: str) -> List[str]:
    """Extracts Indian mobile numbers (+91-XXXXX-XXXXX, 98XXXXXXXX, etc.)."""
    pattern = r'(?:\+?91[\s\-]?)?(?:[6789]\d{4}[\s\-]?\d{5}|[6789]\d{9})\b'
    matches = re.findall(pattern, text)
    cleaned = []
    for m in matches:
        digits = "".join(ch for ch in m if ch.isdigit())
        if len(digits) == 10:
            cleaned.append(f"+91{digits}")
        elif len(digits) == 12 and digits.startswith("91"):
            cleaned.append(f"+{digits}")
    return list(dict.fromkeys(cleaned))


def extract_emails(text: str) -> List[Dict[str, Any]]:
    """Extracts emails and categorizes each as free provider vs corporate."""
    pattern = r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
    results = []
    for match in re.finditer(pattern, text):
        email_addr = match.group(0).lower()
        domain = match.group(1).lower()
        is_free = domain in FREE_EMAIL_DOMAINS
        results.append({
            "email": email_addr,
            "domain": domain,
            "is_free_provider": is_free,
            "is_known_corp": domain in KNOWN_CORP_DOMAINS
        })
    # Remove duplicates
    unique = []
    seen = set()
    for item in results:
        if item["email"] not in seen:
            seen.add(item["email"])
            unique.append(item)
    return unique


def extract_upi_ids(text: str) -> List[str]:
    """
    Extracts Indian UPI handles / Virtual Payment Addresses (VPAs).
    Examples: fastjobpay@oksbi, hr.tcslogistics@icici, earnfast.merchant@paytm
    """
    # Exclude common email domains to prevent false positives
    vpa_pattern = r'\b([a-zA-Z0-9.\-_]{3,64})@(okhdfcbank|oksbi|okaxis|okicici|paytm|upi|gpay|ybl|axl|ibl|barodampay|federal|allbank|postbank|icici|sbi|hdfc|kotak|pnb)\b'
    matches = re.finditer(vpa_pattern, text, re.IGNORECASE)
    upis = [m.group(0).lower() for m in matches]
    return list(dict.fromkeys(upis))


def extract_urls(text: str) -> List[Dict[str, Any]]:
    """Extracts URLs and flags suspicious TLDs."""
    pattern = r'https?://(?:www\.)?([a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+)'
    matches = re.finditer(pattern, text, re.IGNORECASE)
    urls = []
    for m in matches:
        full_url = m.group(0)
        domain = full_url.split('/')[2].lower()
        is_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        urls.append({
            "url": full_url,
            "domain": domain,
            "is_suspicious_tld": is_suspicious_tld
        })
    return urls


def extract_telegram_handles(text: str) -> List[str]:
    """Extracts Telegram handles and t.me links."""
    pattern = r'(?:t\.me/|@)([a-zA-Z0-9_]{5,32})'
    handles = []
    for match in re.finditer(pattern, text, re.IGNORECASE):
        handles.append(f"@{match.group(1).lstrip('@')}")
    return list(dict.fromkeys(handles))


def extract_salaries(text: str) -> List[Dict[str, Any]]:
    """
    Extracts offered compensation figures:
    - LPA: e.g. 6.5 LPA, 3.85 LPA, 12 Lakhs
    - Monthly: e.g. 85,000/- Per Month, Rs 48,000, 35000/month
    """
    salaries = []
    
    # 1. LPA Pattern
    lpa_pattern = r'(\d+(?:\.\d+)?)\s*(?:lpa|lakhs?\s*per\s*annum|lakhs?\s*ctc|lac\s*ctc)\b'
    for m in re.finditer(lpa_pattern, text, re.IGNORECASE):
        val = float(m.group(1))
        salaries.append({
            "type": "LPA",
            "value_lpa": val,
            "raw_text": m.group(0),
            "estimated_monthly_inr": round((val * 100000) / 12, 2)
        })

    # 2. Monthly Pattern
    monthly_pattern = r'(?:inr|rs\.?|monthly(?:\s*salary|\s*stipend)?)\s*:?\s*(\d{1,3}(?:,\d{3})+|\d{4,6})\s*(?:/-\s*per\s*month|per\s*month|/month|pm)?'
    for m in re.finditer(monthly_pattern, text, re.IGNORECASE):
        raw_num = m.group(1).replace(",", "")
        val = float(raw_num)
        # Avoid mixing up fee deposits (usually 1000-5000) with monthly salary (usually >= 15000)
        if val >= 15000:
            salaries.append({
                "type": "Monthly",
                "value_monthly_inr": val,
                "value_lpa": round((val * 12) / 100000, 2),
                "raw_text": m.group(0)
            })

    return salaries


def extract_fee_demands(text: str) -> List[Dict[str, Any]]:
    """
    Extracts payment, fee, deposit, or kit charge demands.
    Genuine corporate employers in India NEVER charge candidates.
    """
    fee_keywords = [
        "registration fee", "security deposit", "refundable fee", "kit fee",
        "laptop deposit", "training fee", "gate pass fee", "processing fee",
        "stamp duty", "agreement fee", "courier insurance", "uniform fee",
        "medical examination fee", "vpn license", "software charges",
        "paisa bhejo", "gpay", "phonepe", "paytm", "refundable security"
    ]
    
    text_lower = text.lower()
    demands = []

    for kw in fee_keywords:
        if kw in text_lower:
            # Try to capture the amount mentioned near the keyword
            window_pattern = rf'{re.escape(kw)}[^\.\n]{{0,60}}(?:rs\.?|inr)\s*(\d{{1,3}}(?:,\d{{3}})*|\d{{3,6}})'
            amt_match = re.search(window_pattern, text_lower)
            amount = None
            if amt_match:
                try:
                    amount = float(amt_match.group(1).replace(",", ""))
                except Exception:
                    amount = None

            demands.append({
                "keyword": kw,
                "detected_amount_inr": amount
            })

    return demands


def extract_coercion_phrases(text: str) -> List[str]:
    """Detects pressure, blackmail, and fake legal threats."""
    coercion_keywords = [
        "ipc section 420", "ipc 420", "legal notice", "blacklist naukri",
        "blacklisted across all it companies", "contract cancellation charges",
        "within 2 hours", "today before 6:00 pm", "urgent notice",
        "without written test or technical interview", "direct selection order",
        "diversity corporate quota", "guaranteed job"
    ]
    text_lower = text.lower()
    return [kw for kw in coercion_keywords if kw in text_lower]


def extract_text_from_file_bytes(filename: str, content_bytes: bytes) -> str:
    """
    Extracts plain text from file bytes.
    Supports TXT, PDF (pdfplumber), DOCX (python-docx), and Images (pytesseract/PIL).
    """
    fn_lower = filename.lower()

    # 1. Plain Text
    if fn_lower.endswith(".txt"):
        return content_bytes.decode("utf-8", errors="ignore")

    # 2. PDF Extraction using pdfplumber
    if fn_lower.endswith(".pdf"):
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(content_bytes)) as pdf:
                pages_text = []
                for p in pdf.pages:
                    txt = p.extract_text()
                    if txt:
                        pages_text.append(txt)
                return "\n".join(pages_text)
        except Exception as e:
            return f"[PDF Extraction Error: {e}]"

    # 3. DOCX Extraction using python-docx
    if fn_lower.endswith(".docx"):
        try:
            import docx
            doc = docx.Document(io.BytesIO(content_bytes))
            return "\n".join([p.text for p in doc.paragraphs if p.text.strip()])
        except Exception as e:
            return f"[DOCX Extraction Error: {e}]"

    # 4. Image OCR using PIL and pytesseract (if available)
    if any(fn_lower.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".webp"]):
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(content_bytes))
            try:
                import pytesseract
                ocr_text = pytesseract.image_to_string(img)
                if ocr_text.strip():
                    return ocr_text
            except Exception:
                pass
            return f"[Image uploaded: {filename} ({img.width}x{img.height})]"
        except Exception as e:
            return f"[Image Extraction Error: {e}]"

    return content_bytes.decode("utf-8", errors="ignore")


TECH_STACK_AND_GENERIC_WORDS = {
    "google cloud", "google cloud platform", "gcp", "google analytics", "google workspace",
    "google docs", "google sheets", "amazon web services", "aws", "microsoft azure",
    "azure", "microsoft office", "office 365", "microsoft excel", "github", "gitlab",
    "docker", "kubernetes", "jira", "slack", "mongodb", "mysql", "postgresql", "redis",
    "kafka", "linux", "windows", "android", "ios", "react", "react.js", "reactjs",
    "angular", "vue", "vue.js", "node", "node.js", "nodejs", "python", "java", "c++",
    "golang", "figma", "tableau", "power bi", "terraform", "ci/cd", "rest api", "graphql",
    "html", "css", "javascript", "typescript", "spring boot", "django", "fastapi",
    "flask", "spark", "hadoop", "sql", "nosql", "devops",
    # Job portals & generic headers
    "linkedin", "naukri", "indeed", "glassdoor", "internshala", "foundit", "unstop",
    "job description", "about the job", "about the role", "about us", "about you",
    "key responsibilities", "responsibilities", "requirements", "qualifications",
    "preferred qualifications", "minimum qualifications", "skills required", "skills",
    "what you will do", "who you are", "role overview", "full time", "part time",
    "contract", "internship", "remote", "hybrid", "on-site", "bengaluru", "bangalore",
    "mumbai", "delhi", "hyderabad", "pune", "chennai", "kolkata", "noida", "gurgaon",
    "gurugram", "ahmedabad", "india", "usa", "uk", "singapore", "dubai",
    "apply now", "easy apply", "applicants", "reposted", "act", "acts", "product", "products",
    "project", "projects", "contact", "contacts", "the job", "the role", "our team",
    "the company", "the organization", "company overview"
}

ROLE_INDICATORS = [
    "engineer", "developer", "manager", "lead", "analyst", "specialist",
    "architect", "associate", "intern", "designer", "consultant", "officer",
    "executive", "sde", "qa", "tester", "scientist", "administrator",
    "full stack", "frontend", "backend", "devops", "trainee"
]

LOCATION_INDICATORS = [
    "bengaluru", "bangalore", "mumbai", "pune", "delhi", "noida", "gurgaon",
    "gurugram", "hyderabad", "chennai", "kolkata", "ahmedabad", "india",
    "remote", "hybrid", "on-site", "applicants", "reposted", "full-time",
    "contract", "days ago", "hours ago", "weeks ago", "months ago"
]

FIELD_EXCLUSIONS = [
    "location", "skills", "experience", "salary", "stipend", "notice",
    "qualification", "responsibilities", "requirements", "about", "job type",
    "work mode", "industry", "posted", "openings", "education", "key skills"
]

GENERIC_ABOUT_WORDS = {
    "job", "the job", "role", "the role", "position", "the position",
    "company", "the company", "organization", "the organization",
    "team", "our team", "us", "you", "work", "internship", "project"
}


def clean_company_name(name: str) -> Optional[str]:
    """Cleans candidate company name, trimming prefixes, suffixes, and rejecting tech stack names."""
    if not name:
        return None
    cleaned = re.sub(r'[\r\n\t]+', ' ', name).strip()
    cleaned = re.sub(r'^(?:at|@|the|for|hiring at)\s+', '', cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r'[\s:;,\.\-–—]+$', '', cleaned).strip()
    cleaned = re.sub(r'^[\s:;,\.\-–—]+', '', cleaned).strip()

    if len(cleaned) < 2 or len(cleaned) > 70:
        return None
    cleaned_lower = cleaned.lower()
    if cleaned_lower in TECH_STACK_AND_GENERIC_WORDS or cleaned_lower in GENERIC_ABOUT_WORDS:
        return None
    if any(cleaned_lower == w.lower() for w in TECH_STACK_AND_GENERIC_WORDS):
        return None
    for fe in FIELD_EXCLUSIONS:
        if cleaned_lower.startswith(f"{fe}:") or cleaned_lower.startswith(f"{fe} -"):
            return None
        if cleaned_lower == fe:
            return None
    return cleaned


def extract_company_name(text: str, explicit_company: Optional[str] = None) -> Optional[str]:
    """
    Intelligently extracts the hiring company / employer name from:
    1. Explicit user input
    2. Explicit labeled fields ("Company: Razorpay", "Employer: Zepto")
    3. LinkedIn copy-paste format (Line 0 = Role, Line 1 = Company, Line 2 = Location)
    4. Headline announcements ("Cognizant is hiring", "At Razorpay, we...")
    5. Legal entity registered names ("XYZ Technologies Private Limited")
    """
    if explicit_company and explicit_company.strip():
        cleaned = clean_company_name(explicit_company.strip())
        if cleaned:
            return cleaned

    if not text or not text.strip():
        return None

    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]

    # Strategy 1: Explicit labeled fields (e.g. "Company: Razorpay", "Employer: XYZ")
    labeled_patterns = [
        r'(?im)^\s*(?:Company|Employer|Organization|Hiring Company|Client)(?:\s*Name)?\s*[:\-–]\s*([A-Za-z0-9&.,\'’\- ]{2,60})',
        r'(?i)\b(?:Company|Employer|Organization|Hiring Company|Client)(?:\s*Name)?\s*[:\-–]\s*([A-Za-z0-9&.,\'’\- ]{2,60})',
        r'(?im)^\s*(?:Hiring for|Hiring on behalf of)\s*[:\-–]?\s*([A-Za-z0-9&.,\'’\- ]{2,60})',
        r'(?i)\b(?:Offer Letter from|Appointment Letter from)\s*([A-Za-z0-9&.,\'’\- ]{2,60})',
    ]
    for pat in labeled_patterns:
        match = re.search(pat, text)
        if match:
            candidate = clean_company_name(match.group(1))
            if candidate:
                return candidate

    # Strategy 2: LinkedIn Top Card Pattern (Title on Line 0, Company on Line 1, Location on Line 2)
    if len(lines) >= 2:
        line0 = lines[0]
        line0_lower = line0.lower()
        is_line0_role = any(role in line0_lower for role in ROLE_INDICATORS)

        # Check if line 0 is "<Role> at <Company>" or "<Role> · <Company>"
        inline_at = re.search(r'(?i)^(.+?)\s+(?:at|@)\s+([A-Za-z0-9&.,\'’\- ]{2,50})$', line0)
        if inline_at:
            cand = clean_company_name(inline_at.group(2))
            if cand:
                return cand

        inline_dot = re.search(r'^(.+?)\s*·\s*([A-Za-z0-9&.,\'’\- ]{2,50})(?:\s*·.*)?$', line0)
        if inline_dot and not any(loc in inline_dot.group(2).lower() for loc in LOCATION_INDICATORS):
            cand = clean_company_name(inline_dot.group(2))
            if cand:
                return cand

        # If line 0 is a role title, test line 1 as company name
        if is_line0_role and len(lines) >= 2:
            line1 = lines[1]
            line1_cand = clean_company_name(line1)
            line2_lower = lines[2].lower() if len(lines) > 2 else ""
            is_line2_location_or_meta = any(loc in line2_lower for loc in LOCATION_INDICATORS)

            if line1_cand and (is_line2_location_or_meta or len(lines) == 2 or len(line1.split()) <= 4):
                if not any(role in line1.lower() for role in ROLE_INDICATORS) and not any(loc in line1.lower() for loc in LOCATION_INDICATORS):
                    return line1_cand

    # Strategy 3: Introductions & Announcements ("Cognizant is hiring", "At Razorpay, we", "Welcome to Swiggy")
    intro_patterns = [
        r'(?im)^\s*About\s+(?:the\s+)?(?!(?:job|role|position|team|company|organization|us|you)\b)([A-Z][A-Za-z0-9&.,\'’\- ]{1,40}?)(?:\s*[:\-–]|\s*\n|\s+is\b|\s+was\b)',
        r'(?i)\bAt\s+([A-Z][A-Za-z0-9&.,\'’\- ]{1,40}?),\s*(?:we|our)\b',
        r'(?i)\bWelcome to\s+([A-Z][A-Za-z0-9&.,\'’\- ]{1,40}?)[!.,\n]',
        r'(?im)^([A-Z][A-Za-z0-9&.,\'’\- ]{1,40}?)\s+(?:is hiring|is looking for|announces openings?)\b',
        r'(?i)\b([A-Z][A-Za-z0-9&.,\'’\- ]{2,40}?)\s+(?:is hiring|is looking for|announces openings?)\b',
        r'(?i)\bJoin\s+(?:the\s+)?([A-Z][A-Za-z0-9&.,\'’\- ]{2,40}?)\s+team\b',
        r'(?i)\bWe at\s+([A-Z][A-Za-z0-9&.,\'’\- ]{2,50}?)\s+(?:are pleased|are thrilled|welcome)\b',
    ]
    for pat in intro_patterns:
        match = re.search(pat, text)
        if match:
            candidate = clean_company_name(match.group(1))
            if candidate:
                return candidate

    # Strategy 4: Full Legal Entity Name (e.g. "Razorpay Software Private Limited")
    legal_pattern = r'\b([A-Z][A-Za-z0-9&.,\'’\- ]{2,50}?\s+(?:Private Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|Corporation|Corp\.?))\b'
    legal_matches = re.findall(legal_pattern, text)
    for lm in legal_matches:
        candidate = clean_company_name(lm)
        if candidate:
            return candidate

    return None


def extract_all_entities(text: str, explicit_company: Optional[str] = None) -> Dict[str, Any]:
    """Runs all extractors on input text and returns a unified entity dictionary."""
    return {
        "company_name": extract_company_name(text, explicit_company=explicit_company),
        "cin": extract_cin(text),
        "gstin": extract_gstin(text),
        "pan": extract_pan(text),
        "phones": extract_phone_numbers(text),
        "emails": extract_emails(text),
        "upi_ids": extract_upi_ids(text),
        "urls": extract_urls(text),
        "telegrams": extract_telegram_handles(text),
        "salaries": extract_salaries(text),
        "fee_demands": extract_fee_demands(text),
        "coercion_phrases": extract_coercion_phrases(text)
    }

