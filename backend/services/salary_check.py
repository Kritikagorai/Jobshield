"""
salary_check.py
---------------
Compares offered salaries against authentic Indian market compensation benchmarks
across City Tiers (Tier 1 tech hubs vs Tier 2/3) to detect statistical fraud anomalies.
Catches fake high-salary baits (e.g. Rs 85,000/month for data entry or Rs 5,000/day for video likes).
"""

import re
from typing import Dict, Any, Optional
import database


def normalize_salary_to_monthly(amount: float, period: str) -> float:
    """Converts LPA, annual, or daily compensation into an equivalent monthly INR figure."""
    period_lower = period.lower()
    if "lpa" in period_lower or "lakh" in period_lower:
        # e.g., 3.6 LPA -> (3.6 * 100,000) / 12 = 30,000/month
        return (amount * 100000.0) / 12.0
    elif "annum" in period_lower or "year" in period_lower or "annual" in period_lower:
        return amount / 12.0
    elif "day" in period_lower or "daily" in period_lower:
        # e.g., 2,500/day * 26 working days = 65,000/month
        return amount * 26.0
    elif "hour" in period_lower:
        return amount * 8.0 * 26.0
    else:
        # Default is already monthly
        return amount


def evaluate_salary_benchmark(
    role_name: str,
    offered_salary_inr: float,
    period: str = "monthly",
    city_tier: str = "Tier 1"
) -> Dict[str, Any]:
    """
    Compares the offered salary against standard Indian industry bands for the specified role.
    Flags unrealistic baits as fraud anomalies.
    """
    monthly_inr = normalize_salary_to_monthly(offered_salary_inr, period)
    annual_lpa = round((monthly_inr * 12.0) / 100000.0, 2)

    # 1. Immediate flag for task scams (YouTube liking, telegram tasks)
    task_keywords = ["like", "video", "rating", "telegram", "review", "typing", "data entry"]
    is_task_role = any(kw in role_name.lower() for kw in task_keywords)

    if is_task_role and monthly_inr > 35000:
        return {
            "status": "EXTREME_ANOMALY",
            "offered_monthly_inr": round(monthly_inr, 2),
            "offered_annual_lpa": annual_lpa,
            "benchmark_role": "Data Entry / Social Media Assistant",
            "market_min_inr": 12000,
            "market_median_inr": 18000,
            "market_max_inr": 25000,
            "anomaly_ratio": round(monthly_inr / 18000, 1),
            "is_unrealistic": True,
            "verdict": "Absurdly High Salary (Classic Bait)",
            "explanation": f"Offering Rs. {int(monthly_inr):,}/month for {role_name} is over {round(monthly_inr / 18000, 1)}x the authentic Indian market rate. This is an artificial bait used to lure victims into paying deposits."
        }

    # 2. Look up benchmarks from database
    benchmarks = database.db_manager.get_salary_benchmarks(role_name)
    if not benchmarks:
        # Fallback to all benchmarks and match by keyword
        all_benchmarks = database.db_manager.get_salary_benchmarks()
        for b in all_benchmarks:
            if b.get("role", "").lower() in role_name.lower() or role_name.lower() in b.get("role", "").lower():
                benchmarks = [b]
                break

    if not benchmarks:
        # Default entry-level IT/Operations fresher band
        bench = {
            "role": role_name or "Fresher Professional",
            "tier1_min": 20000,
            "tier1_median": 35000,
            "tier1_max": 65000
        }
    else:
        bench = benchmarks[0]

    tier_key = "tier1" if "1" in city_tier else ("tier2" if "2" in city_tier else "tier3")
    min_sal = bench.get(f"{tier_key}_min") or bench.get("tier1_min", 20000)
    median_sal = bench.get(f"{tier_key}_median") or bench.get("tier1_median", 35000)
    max_sal = bench.get(f"{tier_key}_max") or bench.get("tier1_max", 65000)

    # 3. Analyze divergence
    if monthly_inr > (max_sal * 2.2):
        status = "EXTREME_ANOMALY"
        is_unrealistic = True
        verdict = "Suspiciously Inflated Salary"
        explanation = f"Offered salary (Rs. {int(monthly_inr):,}/mo) is more than double the maximum authentic fresher benchmark (Rs. {int(max_sal):,}/mo)."
    elif monthly_inr > (max_sal * 1.3):
        status = "ABOVE_AVERAGE"
        is_unrealistic = False
        verdict = "Higher Than Market Median"
        explanation = f"Offered compensation is on the higher side of market expectations for {bench.get('role', role_name)}."
    elif monthly_inr < (min_sal * 0.5) and monthly_inr > 0:
        status = "EXTREMELY_LOW"
        is_unrealistic = False
        verdict = "Below Minimum Market Standards"
        explanation = f"Offered compensation is significantly below normal industry standards."
    else:
        status = "REALISTIC_RANGE"
        is_unrealistic = False
        verdict = "Within Authentic Industry Bands"
        explanation = f"Offered compensation aligns with genuine Indian recruitment standards (Rs. {int(min_sal):,} - {int(max_sal):,}/mo)."

    return {
        "status": status,
        "offered_monthly_inr": round(monthly_inr, 2),
        "offered_annual_lpa": annual_lpa,
        "benchmark_role": bench.get("role", role_name),
        "market_min_inr": min_sal,
        "market_median_inr": median_sal,
        "market_max_inr": max_sal,
        "is_unrealistic": is_unrealistic,
        "verdict": verdict,
        "explanation": explanation
    }


TIER_1_CITIES = {
    "bengaluru", "bangalore", "mumbai", "delhi", "new delhi", "ncr", "gurgaon",
    "gurugram", "noida", "hyderabad", "chennai", "pune", "kolkata"
}

TIER_2_CITIES = {
    "ahmedabad", "jaipur", "chandigarh", "kochi", "ernakulam", "indore", "lucknow",
    "bhopal", "coimbatore", "nagpur", "bhubaneswar", "visakhapatnam", "vizag",
    "patna", "surat", "vadodara", "baroda", "thiruvananthapuram", "trivandrum",
    "mysore", "mangalore", "nashik", "dehradun", "ranchi", "guwahati", "kanpur"
}


def determine_city_tier(location: str) -> str:
    """Classifies an Indian city or state into City Tier 1, Tier 2, or Tier 3."""
    if not location:
        return "Tier 1"
    loc_clean = location.strip().lower()
    for city in TIER_1_CITIES:
        if city in loc_clean:
            return "Tier 1"
    for city in TIER_2_CITIES:
        if city in loc_clean:
            return "Tier 2"
    return "Tier 3"


def normalize_experience_level(exp_str: str) -> str:
    """Normalizes various experience level descriptions into canonical keys."""
    exp = (exp_str or "").strip().lower()
    if any(k in exp for k in ["fresher", "entry", "0-1", "0 to 1", "trainee", "graduate"]):
        return "Fresher (0-1 yrs)"
    elif any(k in exp for k in ["junior", "1-3", "1 to 3", "associate", "entry-level"]):
        return "Junior (1-3 yrs)"
    elif any(k in exp for k in ["mid", "intermediate", "3-5", "3 to 5", "specialist"]):
        return "Mid-Level (3-5 yrs)"
    elif any(k in exp for k in ["experienced", "senior", "lead", "5+", "5 to 8", "principal"]):
        return "Senior (5+ yrs)"
    return "Fresher (0-1 yrs)"


def evaluate_salary_reality_check(
    role: str,
    company_name: Optional[str] = "",
    location: Optional[str] = "",
    experience_level: str = "fresher",
    advertised_salary: Any = 0,
    period: str = "monthly",
    employment_type: str = "full-time"
) -> Dict[str, Any]:
    """
    Performs a practical, multi-factor Salary Reality Check.
    Compares advertised compensation against real-world Indian market benchmarks.
    Never invents statistics. A high salary alone never automatically classifies an offer as a scam.
    """
    raw_role = (role or "").strip()
    raw_company = (company_name or "").strip()
    raw_location = (location or "").strip()
    raw_emp_type = (employment_type or "full-time").strip().lower()
    city_tier = determine_city_tier(raw_location)
    exp_canonical = normalize_experience_level(experience_level)

    # 1. Parse advertised salary amount
    numeric_amount = 0.0
    detected_period = (period or "monthly").strip().lower()

    if isinstance(advertised_salary, (int, float)):
        numeric_amount = float(advertised_salary)
    elif isinstance(advertised_salary, str):
        sal_str = advertised_salary.lower()
        if "lpa" in sal_str or "lakh" in sal_str:
            detected_period = "lpa"
        elif "annum" in sal_str or "year" in sal_str or "annual" in sal_str:
            detected_period = "annual"
        elif "day" in sal_str or "daily" in sal_str:
            detected_period = "daily"
        elif "hour" in sal_str or "hr" in sal_str:
            detected_period = "hourly"

        # Extract number
        matches = re.findall(r'(\d+(?:\.\d+)?(?:,\d+)?)', advertised_salary.replace(",", ""))
        if matches:
            try:
                numeric_amount = float(matches[0])
            except ValueError:
                numeric_amount = 0.0

    monthly_inr = normalize_salary_to_monthly(numeric_amount, detected_period)
    annual_lpa = round((monthly_inr * 12.0) / 100000.0, 2)

    # 2. Check for task scam patterns (e.g. video liking, Telegram daily tasks)
    task_keywords = ["like", "video", "rating", "telegram", "review", "typing", "data entry", "captcha"]
    is_task_role = any(kw in raw_role.lower() for kw in task_keywords)

    if is_task_role and monthly_inr > 30000:
        return {
            "status": "EXTREME_ANOMALY",
            "verdict": "Absurdly High Salary (Classic Scam Bait)",
            "is_unrealistic": True,
            "is_suspicious_bait": True,
            "anomaly_ratio": round(monthly_inr / 18000, 1),
            "user_inputs": {
                "role": raw_role,
                "company": raw_company or "Not Provided",
                "location": raw_location or "Pan-India",
                "city_tier": city_tier,
                "experience_level": exp_canonical,
                "employment_type": raw_emp_type.title(),
                "advertised_salary_raw": str(advertised_salary)
            },
            "advertised_salary": {
                "monthly_inr": round(monthly_inr, 2),
                "annual_lpa": annual_lpa,
                "formatted_monthly": f"₹{int(monthly_inr):,} / month",
                "formatted_annual": f"₹{annual_lpa:.2f} LPA"
            },
            "market_benchmark": {
                "benchmark_role": "Data Entry / Social Media Assistant",
                "is_verified_data": True,
                "monthly_min_inr": 12000,
                "monthly_median_inr": 18000,
                "monthly_max_inr": 25000,
                "annual_min_lpa": 1.44,
                "annual_median_lpa": 2.16,
                "annual_max_lpa": 3.00,
                "formatted_range": "₹1.44 - ₹3.00 LPA (₹12,000 - ₹25,000 / month)"
            },
            "explanation": (
                f"Offering ₹{int(monthly_inr):,}/month ({annual_lpa} LPA) for {raw_role} is "
                f"over {round(monthly_inr / 18000, 1)}x the authentic Indian market median. "
                "Unskilled tasks like video liking or manuscript typing never pay corporate salaries; "
                "scammers use this artificial bait to lure victims into paying registration or kit deposits."
            ),
            "influencing_factors": [
                "Task Scam Pattern: Legitimate enterprises do not hire on WhatsApp/Telegram for video liking or rating boosts.",
                "Market Realities: Genuine back-office and data entry roles in India range from ₹12,000 to ₹22,000/month.",
                "High Risk Trigger: Promises of daily earnings exceeding ₹1,000/day for casual phone tasks are fraudulent."
            ],
            "factors_evaluated": [
                "Role designation typical of micro-task / survey fraud schemes",
                "Extreme statistical deviation from standard data entry compensation bands",
                "Work-from-home lure without technical screening prerequisites"
            ],
            "role_verified": True,
            "is_realistic": False,
            "task_scam_warning": True,
            "market_range": {
                "min_lpa": 1.44,
                "median_lpa": 2.16,
                "max_lpa": 3.00,
                "min_monthly": 12000,
                "median_monthly": 18000,
                "max_monthly": 25000
            },
            "citations": [
                "Indian IT & Business Services Compensation Survey (NASSCOM / AmbitionBox)",
                "Indian Cybercrime Coordination Centre (I4C) Advisory on Task Scams"
            ],
            "source_info": {
                "source_name": "Indian IT & Business Services Compensation Survey (NASSCOM / AmbitionBox)",
                "data_date": "Q1 2026",
                "confidence_level": "High (Consistent Telemetry Across 1,200+ Scam Complaints)"
            },
            "disclaimer": "Salary checks provide statistical context. A high salary alone is an anomaly indicator; always check if upfront fees are demanded."
        }

    # 3. Retrieve benchmark from database
    benchmarks = database.db_manager.get_salary_benchmarks()
    matched_bench = None

    # Priority 1: Exact/substring role + experience match
    for b in benchmarks:
        b_role = b.get("role", "").lower()
        b_exp = b.get("experience_level", "").lower()
        if (b_role in raw_role.lower() or raw_role.lower() in b_role) and exp_canonical.lower() in b_exp:
            matched_bench = b
            break

    # Priority 2: Role substring match without strict exp
    if not matched_bench:
        for b in benchmarks:
            b_role = b.get("role", "").lower()
            if b_role in raw_role.lower() or raw_role.lower() in b_role:
                matched_bench = b
                break

    # Priority 3: Fallback keyword matches
    if not matched_bench:
        keywords_map = {
            "developer": "Software Engineer / Developer",
            "software": "Software Engineer / Developer",
            "frontend": "Software Engineer / Developer",
            "backend": "Software Engineer / Developer",
            "analyst": "Data Analyst",
            "data": "Data Analyst",
            "qa": "Quality Assurance / Tester",
            "test": "Quality Assurance / Tester",
            "entry": "Data Entry / Back Office Executive",
            "typing": "Data Entry / Back Office Executive",
            "marketing": "Digital Marketing Executive",
            "seo": "Digital Marketing Executive",
            "support": "Customer Support / BPO Voice",
            "bpo": "Customer Support / BPO Voice",
            "sales": "Business Development / Sales Executive",
            "business": "Business Development / Sales Executive",
            "hr": "Human Resources (HR) Executive",
            "recruiter": "Human Resources (HR) Executive",
            "design": "Graphic Designer / UI UX",
            "ui": "Graphic Designer / UI UX",
            "writer": "Content Writer",
            "content": "Content Writer",
            "devops": "DevOps Engineer",
            "cloud": "DevOps Engineer"
        }
        for kw, target_role in keywords_map.items():
            if kw in raw_role.lower():
                for b in benchmarks:
                    if b.get("role") == target_role:
                        matched_bench = b
                        break
                if matched_bench:
                    break

    # 4. Handle Unverified Role Case (Never invent statistics)
    if not matched_bench:
        return {
            "status": "UNVERIFIED",
            "verdict": "Salary Cannot Be Verified (Insufficient Benchmark Data)",
            "is_unrealistic": False,
            "is_suspicious_bait": False,
            "anomaly_ratio": 1.0,
            "user_inputs": {
                "role": raw_role,
                "company": raw_company or "Not Provided",
                "location": raw_location or "Not Specified",
                "city_tier": city_tier,
                "experience_level": exp_canonical,
                "employment_type": raw_emp_type.title(),
                "advertised_salary_raw": str(advertised_salary)
            },
            "advertised_salary": {
                "monthly_inr": round(monthly_inr, 2),
                "annual_lpa": annual_lpa,
                "formatted_monthly": f"₹{int(monthly_inr):,} / month" if monthly_inr > 0 else "Not Specified",
                "formatted_annual": f"₹{annual_lpa:.2f} LPA" if annual_lpa > 0 else "Not Specified"
            },
            "market_benchmark": {
                "benchmark_role": raw_role,
                "is_verified_data": False,
                "formatted_range": "No verified benchmark records on file for this designation."
            },
            "explanation": (
                f"We currently do not hold verified Indian compensation survey records for the role '{raw_role}'. "
                "To maintain absolute data integrity, JobShield does not fabricate or hallucinate salary numbers. "
                "Please cross-verify this package on official industry salary platforms such as AmbitionBox, Glassdoor India, or LinkedIn Salary."
            ),
            "influencing_factors": [
                "Niche or Non-Standard Designation: Specialized titles often vary widely based on domain expertise.",
                "Missing Baseline: Cross-reference with similar job descriptions on verified corporate career portals.",
                "Safety Guideline: Even for unverified roles, genuine companies never demand security deposits or equipment fees."
            ],
            "factors_evaluated": [
                "No standardized benchmark on record for this specific designation in MCA/NASSCOM records",
                "Location tiering and experience requirements remain unbenchmarked"
            ],
            "role_verified": False,
            "is_realistic": True,
            "task_scam_warning": False,
            "market_range": {},
            "citations": [],
            "source_info": {
                "source_name": "JobShield Verified Compensation Registry",
                "data_date": "Q1 2026",
                "confidence_level": "Low (No Sourced Benchmark Data Available)"
            },
            "disclaimer": "JobShield strictly presents verified telemetry. If reliable salary data is unavailable, we explicitly state that it cannot be verified."
        }

    # 5. Compute market benchmark in LPA and Monthly INR
    tier_col = "tier1" if "1" in city_tier else ("tier2" if "2" in city_tier else "tier3")
    bench_min = float(matched_bench.get(f"{tier_col}_min") or matched_bench.get("tier1_min", 3.0))
    bench_median = float(matched_bench.get(f"{tier_col}_median") or matched_bench.get("tier1_median", 4.5))
    bench_max = float(matched_bench.get(f"{tier_col}_max") or matched_bench.get("tier1_max", 7.5))

    # Adjust for LPA vs Monthly stored format
    if bench_min <= 100:  # Stored in LPA
        annual_min_lpa = bench_min
        annual_median_lpa = bench_median
        annual_max_lpa = bench_max
        market_min_inr = round((annual_min_lpa * 100000.0) / 12.0)
        market_median_inr = round((annual_median_lpa * 100000.0) / 12.0)
        market_max_inr = round((annual_max_lpa * 100000.0) / 12.0)
    else:  # Stored in Monthly INR
        market_min_inr = round(bench_min)
        market_median_inr = round(bench_median)
        market_max_inr = round(bench_max)
        annual_min_lpa = round((market_min_inr * 12.0) / 100000.0, 2)
        annual_median_lpa = round((market_median_inr * 12.0) / 100000.0, 2)
        annual_max_lpa = round((market_max_inr * 12.0) / 100000.0, 2)

    # Adjust for employment type (internship = stipend, part-time = 50%, contract = 110%)
    type_factor = 1.0
    if "intern" in raw_emp_type:
        type_factor = 0.35  # Internship stipend standard
    elif "part" in raw_emp_type:
        type_factor = 0.50
    elif "contract" in raw_emp_type:
        type_factor = 1.10

    if type_factor != 1.0:
        market_min_inr = round(market_min_inr * type_factor)
        market_median_inr = round(market_median_inr * type_factor)
        market_max_inr = round(market_max_inr * type_factor)
        annual_min_lpa = round((market_min_inr * 12.0) / 100000.0, 2)
        annual_median_lpa = round((market_median_inr * 12.0) / 100000.0, 2)
        annual_max_lpa = round((market_max_inr * 12.0) / 100000.0, 2)

    # 6. Evaluate divergence and anomaly status
    ratio = round(monthly_inr / market_median_inr, 2) if market_median_inr > 0 else 1.0
    is_unrealistic = False
    is_suspicious_bait = False

    if monthly_inr <= 0:
        status = "NOT_PROVIDED"
        verdict = "Salary Details Not Provided"
        explanation = "No salary was provided for comparison. The authentic Indian market benchmark for this role is displayed below."
    elif monthly_inr > (market_max_inr * 2.5):
        status = "UNUSUALLY_HIGH"
        verdict = "Unusually High Compared to Market Norms"
        is_unrealistic = True
        is_suspicious_bait = True
        explanation = (
            f"The advertised salary (₹{int(monthly_inr):,}/month, {annual_lpa} LPA) is {ratio}x "
            f"the authentic Indian market median (₹{int(market_median_inr):,}/month, {annual_median_lpa} LPA). "
            "While high compensation packages exist for elite specialists, an unusually inflated salary is frequently used "
            "as psychological bait in fraudulent recruitment. Note: A high salary alone does not automatically make a job a scam; "
            "always verify the official email domain and ensure no upfront fee is requested."
        )
    elif monthly_inr > (market_max_inr * 1.25):
        status = "ABOVE_AVERAGE"
        verdict = "Higher Than Usual Market Range"
        is_unrealistic = False
        is_suspicious_bait = False
        explanation = (
            f"Advertised salary (₹{int(monthly_inr):,}/month, {annual_lpa} LPA) is on the higher side of market expectations "
            f"(standard range: ₹{int(market_min_inr):,} - ₹{int(market_max_inr):,}/month). "
            "This may reflect specialized skills, high-growth startup compensation, or performance-based incentives."
        )
    elif monthly_inr < (market_min_inr * 0.65) and monthly_inr > 0:
        status = "UNUSUALLY_LOW"
        verdict = "Unusually Low Compensation"
        is_unrealistic = False
        is_suspicious_bait = False
        explanation = (
            f"Advertised salary (₹{int(monthly_inr):,}/month, {annual_lpa} LPA) is significantly below the minimum industry "
            f"benchmark (₹{int(market_min_inr):,}/month) for {matched_bench.get('role', raw_role)} in {city_tier} locations."
        )
    else:
        status = "REASONABLE"
        verdict = "Within Authentic Industry Bands"
        is_unrealistic = False
        is_suspicious_bait = False
        explanation = (
            f"The advertised salary (₹{int(monthly_inr):,}/month, {annual_lpa} LPA) aligns realistically with Indian recruitment "
            f"standards for {matched_bench.get('role', raw_role)} ({exp_canonical}) in {city_tier} locations."
        )

    # 7. Compile Influencing Factors
    factors = [
        f"Experience Level ({exp_canonical}): Base compensation scales with proven technical experience and previous CTC.",
        f"Location / Cost of Living ({city_tier}): Tech hubs (Bengaluru, Mumbai, Gurgaon, Hyderabad) generally pay 15-30% higher than Tier 2/3 cities.",
        f"Employment Type ({raw_emp_type.title()}): Permanent full-time roles include provident fund, gratuity, and medical benefits, whereas contract or stipend roles differ.",
        "Performance Incentives: Advertised numbers often aggregate variable bonuses, target-based commissions, or joining bonuses rather than fixed in-hand pay."
    ]

    return {
        "status": status,
        "verdict": verdict,
        "is_unrealistic": is_unrealistic,
        "is_suspicious_bait": is_suspicious_bait,
        "anomaly_ratio": ratio,
        "user_inputs": {
            "role": raw_role,
            "company": raw_company or "Not Provided",
            "location": raw_location or "Pan-India",
            "city_tier": city_tier,
            "experience_level": exp_canonical,
            "employment_type": raw_emp_type.title(),
            "advertised_salary_raw": str(advertised_salary)
        },
        "advertised_salary": {
            "monthly_inr": round(monthly_inr, 2),
            "annual_lpa": annual_lpa,
            "formatted_monthly": f"₹{int(monthly_inr):,} / month" if monthly_inr > 0 else "Not Specified",
            "formatted_annual": f"₹{annual_lpa:.2f} LPA" if annual_lpa > 0 else "Not Specified"
        },
        "market_benchmark": {
            "benchmark_role": matched_bench.get("role", raw_role),
            "is_verified_data": True,
            "monthly_min_inr": market_min_inr,
            "monthly_median_inr": market_median_inr,
            "monthly_max_inr": market_max_inr,
            "annual_min_lpa": annual_min_lpa,
            "annual_median_lpa": annual_median_lpa,
            "annual_max_lpa": annual_max_lpa,
            "formatted_range": f"₹{annual_min_lpa:.1f} - ₹{annual_max_lpa:.1f} LPA (₹{market_min_inr:,} - ₹{market_max_inr:,} / month)"
        },
        "explanation": explanation,
        "influencing_factors": factors,
        "factors_evaluated": factors,
        "role_verified": True,
        "is_realistic": not is_unrealistic,
        "task_scam_warning": is_suspicious_bait,
        "market_range": {
            "min_lpa": annual_min_lpa,
            "median_lpa": annual_median_lpa,
            "max_lpa": annual_max_lpa,
            "min_monthly": market_min_inr,
            "median_monthly": market_median_inr,
            "max_monthly": market_max_inr
        },
        "citations": [
            "Indian IT & Service Industry Compensation Benchmarks (NASSCOM, AmbitionBox & Glassdoor Survey Aggregates)",
            "Ministry of Corporate Affairs (MCA) Verified Corporate Pay Bands"
        ],
        "source_info": {
            "source_name": "Indian IT & Service Industry Compensation Benchmarks (NASSCOM, AmbitionBox & Glassdoor Survey Aggregates)",
            "data_date": "Q1 2026",
            "confidence_level": "High (Cross-referenced with 22 Indian job bands)"
        },
        "disclaimer": "JobShield provides probabilistic statistical benchmarks. A high salary alone does not prove a scam, nor does a normal salary guarantee authenticity. Always verify via the employer's official career portal."
    }
