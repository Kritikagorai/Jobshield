"""
ML Scam Classifier Service for JobShield (Phase 2).
Uses Scikit-learn TF-IDF Vectorization and Cosine Similarity to compare candidate
job offer descriptions against known scam templates from the Indian cybercrime database.
"""
from typing import Dict, List, Any, Optional
import numpy as np

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class MLScamClassifier:
    """Scikit-Learn powered NLP scam pattern matching engine."""

    def __init__(self, templates: Optional[List[Dict[str, Any]]] = None):
        self.templates = templates or []
        self.vectorizer = None
        self.template_matrix = None
        if SKLEARN_AVAILABLE and self.templates:
            self._fit()

    def update_templates(self, templates: List[Dict[str, Any]]):
        """Refreshes templates from the database."""
        self.templates = templates
        if SKLEARN_AVAILABLE and self.templates:
            self._fit()

    def _fit(self):
        """Fits TF-IDF on all template texts."""
        corpus = [t.get("text", "") for t in self.templates]
        self.vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_features=2500
        )
        self.template_matrix = self.vectorizer.fit_transform(corpus)

    def match_similarity(self, text: str) -> Dict[str, Any]:
        """
        Calculates cosine similarity of input text against all known scam templates.
        Returns top matching template, similarity score (0-100), and risk assessment.
        """
        if not text or not text.strip() or not SKLEARN_AVAILABLE or not self.vectorizer:
            return {
                "matched": False,
                "similarity_score": 0.0,
                "template_title": "No match",
                "category": "Unknown",
                "risk_level": "Low"
            }

        try:
            input_vec = self.vectorizer.transform([text])
            sim_scores = cosine_similarity(input_vec, self.template_matrix)[0]
            best_idx = int(np.argmax(sim_scores))
            best_score = float(sim_scores[best_idx])
            best_template = self.templates[best_idx]

            # Convert cosine similarity (-1 to 1) to percentage (0 - 100)
            percentage = round(max(0.0, best_score * 100), 1)

            is_match = percentage >= 28.0  # Threshold for textual scam pattern match

            return {
                "matched": is_match,
                "similarity_percentage": percentage,
                "category": best_template.get("category", "General Fraud"),
                "template_title": best_template.get("title", "Generic Job Scam"),
                "risk_level": best_template.get("risk_level", "High") if is_match else "Low",
                "typical_fee": best_template.get("typical_fee", 0),
                "historical_report_count": best_template.get("report_count", 0)
            }
        except Exception as e:
            return {
                "matched": False,
                "similarity_percentage": 0.0,
                "error": str(e)
            }


# Pre-instantiate using database templates
def get_classifier(templates: List[Dict[str, Any]]) -> MLScamClassifier:
    return MLScamClassifier(templates)
