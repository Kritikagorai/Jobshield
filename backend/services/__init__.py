"""
JobShield Backend Services Package
----------------------------------
Modular rule-based verification, NLP, ML classification, and scoring services.
"""

from .privacy import (
    mask_aadhaar,
    mask_pan,
    mask_phone,
    mask_email,
    mask_sensitive_text,
    mask_entity_dict
)
from .validators import (
    validate_cin,
    validate_gstin,
    validate_pan,
    compute_gstin_checksum
)
from .company_registry import (
    find_company_in_registry,
    get_all_registered_companies,
    verify_company_credentials
)
from .email_domain import (
    is_free_email,
    has_suspicious_tld,
    detect_typosquatting,
    analyze_domain,
    verify_recruiter_domain_mismatch,
    is_safe_url,
    check_domain_registration_age
)
from .red_flags import (
    scan_red_flags
)
from .payment_advisor import (
    evaluate_payment_safety
)
from .pressure_meter import (
    calculate_pressure_score
)
from .similarity import (
    find_similar_scam_templates
)
from .salary_check import (
    evaluate_salary_benchmark,
    normalize_salary_to_monthly,
    evaluate_salary_reality_check,
    determine_city_tier,
    normalize_experience_level
)
from .complaint import (
    generate_cybercrime_complaint
)
from .text_extractor import (
    extract_document_text,
    extract_from_pdf,
    extract_from_docx,
    extract_from_image,
    extract_from_plain_text
)
from .ml_model import (
    ScamClassifier,
    scam_classifier
)
from .scoring import (
    calculate_comprehensive_trust_score
)
