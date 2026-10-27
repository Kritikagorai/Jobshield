"""
pressure_meter.py
-----------------
Quantifies psychological manipulation and artificial pressure tactics:
1. Time Urgency: "within 2 hours", "today before 6 PM", "expires immediately".
2. Secrecy Demands: "do not disclose to parents/friends", "strictly confidential".
3. Intimidation & Blacklisting: "profile will be blacklisted across all IT firms".
4. Seat Scarcity: "only 2 seats left", "immediate deposit needed to hold slot".
"""

import re
from typing import Dict, Any, List

PRESSURE_PATTERNS = [
    {
        "type": "Short Deadline",
        "weight": 25,
        "regex": r'(?:within|in)\s*(?:2|3|4|6|12|24)\s*hours?|before\s*(?:today|evening|6\s*pm|5\s*pm)|expires\s*(?:today|soon|in\s*\d+\s*hours?)'
    },
    {
        "type": "Immediate Action Demand",
        "weight": 20,
        "regex": r'pay\s*(?:immediately|now|urgently)|transfer\s*today|urgent\s*(?:notice|joining|action)|confirm\s*immediately'
    },
    {
        "type": "Blacklist Threat",
        "weight": 35,
        "regex": r'profile\s*(?:will\s*be\s*)?blacklisted|permanently\s*(?:cancelled|blocked|blacklisted)|banned\s*from\s*naukri'
    },
    {
        "type": "Secrecy & Isolation",
        "weight": 25,
        "regex": r'do\s*not\s*(?:discuss|share|disclose)|strictly\s*confidential|keep\s*secret|do\s*not\s*tell\s*(?:anyone|parents|friends)'
    },
    {
        "type": "Artificial Scarcity",
        "weight": 15,
        "regex": r'limited\s*(?:seats|vacancies|slots)|only\s*\d+\s*(?:seats|positions)\s*left|first\s*come\s*first\s*serve'
    }
]


def calculate_pressure_score(text: str) -> Dict[str, Any]:
    """
    Computes a 0 to 100 Pressure Score based on detected manipulation tactics.
    Provides plain-language guidance to help freshers recognize psychological traps.
    """
    if not text:
        return {
            "pressure_score": 0,
            "pressure_level": "Low",
            "signals": [],
            "advice": "No coercive psychological pressure detected."
        }

    detected_signals: List[Dict[str, Any]] = []
    total_score = 0

    for item in PRESSURE_PATTERNS:
        matches = re.findall(item["regex"], text, flags=re.IGNORECASE)
        if matches:
            samples = list(set([m.strip() for m in matches if m.strip()]))[:2]
            detected_signals.append({
                "tactic": item["type"],
                "samples": samples,
                "weight": item["weight"]
            })
            total_score += item["weight"]

    # Cap score at 100
    pressure_score = min(total_score, 100)

    # Determine severity label
    if pressure_score >= 60:
        level = "Extreme"
        advice = "DANGER: High psychological pressure detected! Scammers use false deadlines and threats to prevent you from consulting family or verifying the offer. Stop and do not transfer any money."
    elif pressure_score >= 35:
        level = "High"
        advice = "WARNING: Artificial urgency detected. Legitimate corporations give candidates several days to review offer letters."
    elif pressure_score >= 15:
        level = "Moderate"
        advice = "Mild deadline pressure noted. Double-check official corporate portals before taking action."
    else:
        level = "Low"
        advice = "Normal communication tone with standard timelines."

    return {
        "pressure_score": pressure_score,
        "pressure_level": level,
        "signals": detected_signals,
        "signals_count": len(detected_signals),
        "advice": advice
    }
