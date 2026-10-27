"""
similarity.py
-------------
Measures semantic text similarity between candidate job offers and
known real-world fraud templates using TF-IDF and Cosine Similarity.
Provides an explainable match percentage against historical scam campaigns.
"""

from typing import List, Dict, Any
import database

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


def _jaccard_fallback_similarity(str1: str, str2: str) -> float:
    """Fallback word-overlap similarity when scikit-learn is not installed."""
    words1 = set(str1.lower().split())
    words2 = set(str2.lower().split())
    if not words1 or not words2:
        return 0.0
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    return len(intersection) / len(union)


def find_similar_scam_templates(text: str, top_n: int = 3) -> List[Dict[str, Any]]:
    """
    Compares the given text against known scam templates stored in the database.
    Returns the top N matching templates with their similarity percentages.
    """
    if not text or not text.strip():
        return []

    templates = database.db_manager.get_scam_templates()
    if not templates:
        return []

    template_texts = [t.get("text", "") for t in templates]
    all_corpus = [text] + template_texts

    matches = []

    if SKLEARN_AVAILABLE:
        try:
            vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
            tfidf_matrix = vectorizer.fit_transform(all_corpus)
            query_vec = tfidf_matrix[0:1]
            template_vecs = tfidf_matrix[1:]
            scores = cosine_similarity(query_vec, template_vecs)[0]

            for idx, score in enumerate(scores):
                t = templates[idx]
                pct = round(float(score) * 100, 1)
                matches.append({
                    "id": t.get("id"),
                    "title": t.get("title") or t.get("name", "Unknown Pattern"),
                    "category": t.get("category", "General Fraud"),
                    "similarity_pct": pct,
                    "report_count": t.get("report_count") or t.get("reported_count", 1),
                    "typical_fee": t.get("typical_fee", 0),
                    "template_preview": t.get("text", "")[:120] + "..."
                })
        except Exception as e:
            # Fallback to keyword matching on error
            print(f"[SIMILARITY] Sklearn calculation error: {e}, using fallback.")
            for t in templates:
                sim = _jaccard_fallback_similarity(text, t.get("text", ""))
                matches.append({
                    "id": t.get("id"),
                    "title": t.get("title") or t.get("name", "Unknown Pattern"),
                    "category": t.get("category", "General Fraud"),
                    "similarity_pct": round(sim * 100, 1),
                    "report_count": t.get("report_count") or t.get("reported_count", 1),
                    "typical_fee": t.get("typical_fee", 0),
                    "template_preview": t.get("text", "")[:120] + "..."
                })
    else:
        for t in templates:
            sim = _jaccard_fallback_similarity(text, t.get("text", ""))
            matches.append({
                "id": t.get("id"),
                "title": t.get("title") or t.get("name", "Unknown Pattern"),
                "category": t.get("category", "General Fraud"),
                "similarity_pct": round(sim * 100, 1),
                "report_count": t.get("report_count") or t.get("reported_count", 1),
                "typical_fee": t.get("typical_fee", 0),
                "template_preview": t.get("text", "")[:120] + "..."
            })

    # Sort by highest similarity percentage descending
    matches.sort(key=lambda x: x["similarity_pct"], reverse=True)
    return matches[:top_n]
