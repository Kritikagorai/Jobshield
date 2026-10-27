"""
ml_model.py
-----------
Machine Learning NLP service for job scam classification using Scikit-Learn:
- TF-IDF Vectorizer (word n-grams) + Logistic Regression.
- Automatically checks for the Kaggle 'Fake Job Postings' dataset (fake_job_postings.csv).
- If the dataset file is missing, automatically trains on a built-in balanced
  sample set of 50 realistic Indian genuine vs. scam employment texts so the demo NEVER breaks.
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# 50 Built-in Training Samples (25 Scam Messages/Offers, 25 Genuine Job Descriptions/Letters)
BUILTIN_TRAINING_DATA: List[Tuple[str, int]] = [
    # ------------------ SCAM SAMPLES (Label = 1) ------------------
    ("Congratulations! You are selected for WFH Data Entry. Deposit refundable registration fee of Rs. 1,499 via PhonePe to start work.", 1),
    ("Selected as Associate Trainee at TCS. Apple MacBook Pro is dispatched. Transfer refundable courier insurance of Rs. 2,999 to UPI hr.tcs@icici.", 1),
    ("Work from home part-time. Just like 3 YouTube videos and send screenshot to our Telegram channel @quickearn. Earn Rs. 3,000 daily.", 1),
    ("Urgent appointment order for Airport Ground Staff at IGI Airport. Pay Rs. 4,500 security pass clearance fee via Google Pay today.", 1),
    ("Dear candidate, your resume on Naukri is shortlisted for direct selection without interview. Pay Rs. 1,850 for candidate profile verification.", 1),
    ("Amazon product rating task. Recharge your wallet with Rs. 1,000 to receive merchant orders and earn 20% commission immediately.", 1),
    ("Provisional appointment letter from Infosys HR. Pay Rs. 3,500 laptop courier insurance fee. Offer expires in 2 hours.", 1),
    ("Direct selection under special corporate quota. Transfer Rs. 4,999 today before 6 PM or your Naukri profile will be blacklisted across all IT companies.", 1),
    ("Typing project 500 pages. If daily accuracy is below 90%, legal notice under Section 420 IPC and Rs. 25,000 breach penalty will be filed.", 1),
    ("Dubai hotel supervisor vacancy. Monthly salary 8,500 AED. Transfer Rs. 18,500 towards Ministry of Labor visa clearance processing fee.", 1),
    ("Selected for Hospital Front Desk. Transfer Rs. 2,400 for uniform stitching and Hepatitis vaccination pass to authorized UPI.", 1),
    ("Special Railway Recruitment Cell Direct Quota. Confirm your appointment by paying Rs. 6,800 medical test challan to personal virtual account.", 1),
    ("Earn Rs. 1,500 daily sending promotional SMS from your phone. Send full photos of Aadhaar Card, PAN Card, and blank cancelled cheque.", 1),
    ("Flipkart delivery hub supervisor hiring. Pay Rs. 1,200 uniform and badge delivery fee via Paytm to confirm joining.", 1),
    ("Congratulations! Direct selection in Reliance Jio Digital Store. Pay Rs. 2,200 induction seminar pass fee before Monday.", 1),
    ("Part-time review operator: earn Rs. 5,000 daily by rating Google maps places. Join VIP Telegram group to receive daily prepaid tasks.", 1),
    ("Wipro placement alliance. Selected without assessment. Deposit Rs. 3,200 refundable corporate badge fee to wiprohr@oksbi.", 1),
    ("Crypto arbitrage task: Earn 100 USDT daily from home. Deposit 50 USDT to activate trader workbench.", 1),
    ("Selected for Office Assistant. Transfer Rs. 999 for identity card printing and document file charges. Immediate joining.", 1),
    ("Dear job seeker, immediate opening in MNC bank. Pay Rs. 2,500 gate entry pass fee before attending Zoom interview.", 1),
    ("Data entry typing job: registration charge Rs. 1,200. High daily earnings. Any mistake will attract court summons.", 1),
    ("Selected as Customer Care Executive on WhatsApp. Pay Rs. 1,500 training kit delivery fee to confirmed UPI ID.", 1),
    ("Urgent notice: You have won direct placement at L&T. Deposit Rs. 5,000 refundable security caution money today.", 1),
    ("Online task partner: deposit Rs. 2,000 to unlock higher commission level 2. Withdraw full amount within 10 minutes.", 1),
    ("Appointment letter issued without exam. Transfer medical examination fee of Rs. 3,000 to recruiter GPay immediately.", 1),

    # ------------------ GENUINE SAMPLES (Label = 0) ------------------
    ("Tata Consultancy Services Limited is pleased to offer you the position of Assistant System Engineer with CTC 3.85 LPA. TCS follows a zero-fee recruitment policy.", 0),
    ("Infosys Limited: Offer of employment as Systems Engineer. All background verification expenses are borne fully by Infosys. Report on joining date at Mysore campus.", 0),
    ("Wipro Limited: We are pleased to offer you appointment as Project Engineer. You are not required to pay any deposit, fee, or charge at any point.", 0),
    ("HCL Technologies: Offer letter for Software Developer trainee. Please accept through our official candidate portal careers.hcltech.com within 7 days.", 0),
    ("Tech Mahindra Limited: Letter of Intent for Associate Software Engineer. Merit-based selection based on campus placement rounds.", 0),
    ("Larsen & Toubro: Employment offer as Graduate Engineer Trainee. Joining formalities will be conducted at our Mumbai office. No fees required.", 0),
    ("Job Description: Full Stack Python Developer with 2+ years experience in FastAPI, PostgreSQL, and React. Location: Bengaluru. Standard market CTC.", 0),
    ("Swiggy is hiring Software Development Engineers (SDE-1). Requirements: Data Structures, Algorithms, REST APIs, and System Design.", 0),
    ("Zomato Careers: Operations Executive role in Gurugram. Competitive fixed salary plus quarterly performance incentives.", 0),
    ("Razorpay: We are looking for Frontend Engineers skilled in TypeScript and Next.js. Apply directly via razorpay.com/jobs.", 0),
    ("Flipkart Internet Pvt Ltd: Campus placement offer for Business Analyst. Detailed compensation break-up enclosed in Annexure A.", 0),
    ("HDFC Bank: Official appointment order for Branch Operations Executive. Formal background verification will be conducted by authorized agency.", 0),
    ("ICICI Bank: Probationary Officer training program selection letter. Merit list announced on icicibank.com/careers.", 0),
    ("Zoho Corporation: We are pleased to extend an offer for Product Developer. Joining at Zoho Estancia Chennai campus.", 0),
    ("Freshworks: Offer of employment for Customer Success Specialist. Standard company benefits include medical insurance and provident fund.", 0),
    ("Job Opening: Junior QA Tester. Knowledge of Selenium, pytest, and Git. 5-day work week with hybrid flexibility in Pune.", 0),
    ("Amazon India: Software Development Engineer 2. Technical interview loop completed. Official offer letter dispatched via Amazon internal portal.", 0),
    ("Microsoft India: Invitation for Technical Interview Round 2 for Cloud Solutions Architect position. Join via Teams link.", 0),
    ("Deloitte India: Analyst in Risk Advisory. Formal written assessment and partner interview completed. Welcome to the team.", 0),
    ("Job Description: Content Writer & SEO Specialist. Responsibilities include blog writing, keyword research, and social media scheduling.", 0),
    ("Google India: Software Engineer - Machine Learning. Competitive compensation including base salary, annual bonus, and equity grants.", 0),
    ("Aviation ground staff direct walk-in interview notice published on official airline website. Bring original certificates for verification. No fees.", 0),
    ("Capgemini India: Senior Software Engineer offer letter. Pre-onboarding learning modules available on Capgemini portal.", 0),
    ("Cognizant Technology Solutions: Programmer Analyst Trainee. Official communication strictly through @cognizant.com domain.", 0),
    ("Standard employment agreement: Notice period 60 days, probation period 6 months, medical insurance coverage for employee and dependents.", 0)
]


class ScamClassifier:
    """
    Scikit-learn TF-IDF + Logistic Regression Classifier for Scam Detection.
    Trained on Kaggle dataset or built-in sample data.
    """

    def __init__(self, dataset_path: Optional[str] = None):
        self.model = None
        self.dataset_source = "None"
        self.train_samples_count = 0
        self.is_trained = False
        self._train_pipeline(dataset_path)

    def _train_pipeline(self, dataset_path: Optional[str] = None):
        """Initializes and trains the Scikit-learn TF-IDF + Logistic Regression pipeline."""
        if not SKLEARN_AVAILABLE:
            print("[ML MODEL] Scikit-Learn not installed. Running in heuristic rule-only mode.")
            return

        texts = []
        labels = []

        # 1. Check if Kaggle fake_job_postings.csv exists
        csv_candidates = [
            dataset_path,
            Path(__file__).resolve().parent.parent / "data" / "fake_job_postings.csv",
            Path(__file__).resolve().parent.parent / "data" / "kaggle_fake_jobs.csv"
        ]
        found_csv = next((p for p in csv_candidates if p and Path(p).exists()), None)

        if found_csv:
            try:
                import pandas as pd
                print(f"[ML MODEL] Loading Kaggle dataset from {found_csv}...")
                df = pd.read_csv(found_csv)
                # Expect columns: 'description' or 'text', and 'fraudulent'
                text_col = "description" if "description" in df.columns else ("text" if "text" in df.columns else None)
                label_col = "fraudulent" if "fraudulent" in df.columns else ("label" if "label" in df.columns else None)

                if text_col and label_col:
                    df = df.dropna(subset=[text_col, label_col])
                    texts = df[text_col].astype(str).tolist()
                    labels = df[label_col].astype(int).tolist()
                    self.dataset_source = f"Kaggle Dataset ({Path(found_csv).name})"
                    print(f"[ML MODEL] Successfully loaded {len(texts)} samples from Kaggle dataset.")
            except Exception as e:
                print(f"[ML MODEL] Could not parse Kaggle CSV: {e}. Falling back to built-in dataset.")

        # 2. Fallback to built-in sample set if CSV not found or failed
        if not texts:
            self.dataset_source = "Built-in Sample Set (50 Indian Job & Scam Samples)"
            texts = [item[0] for item in BUILTIN_TRAINING_DATA]
            labels = [item[1] for item in BUILTIN_TRAINING_DATA]

        self.train_samples_count = len(texts)

        # Build pipeline: TF-IDF (1-2 word n-grams) + Logistic Regression
        self.model = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=2500,
                stop_words="english",
                sublinear_tf=True
            )),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=300,
                class_weight="balanced",
                random_state=42
            ))
        ])

        try:
            self.model.fit(texts, labels)
            self.is_trained = True
            print(f"[ML MODEL] Trained successfully on {self.train_samples_count} samples. Source: {self.dataset_source}")
        except Exception as e:
            print(f"[ML MODEL] Model training failed: {e}")
            self.is_trained = False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Predicts scam probability for an input text using the trained model.
        Returns probability (0.0 to 1.0), boolean prediction, confidence, and top indicative tokens.
        """
        if not text or not text.strip():
            return {
                "is_scam": False,
                "scam_probability": 0.0,
                "confidence_pct": 0.0,
                "verdict": "No text provided",
                "top_features": []
            }

        if not self.is_trained or not SKLEARN_AVAILABLE:
            # Simple keyword heuristic fallback
            lower = text.lower()
            scam_words = ["deposit", "courier", "registration fee", "telegram", "paytm", "gpay", "refundable"]
            matches = [w for w in scam_words if w in lower]
            prob = min(0.95, len(matches) * 0.25)
            return {
                "is_scam": prob >= 0.5,
                "scam_probability": round(prob, 2),
                "confidence_pct": round(prob * 100, 1),
                "verdict": "High scam probability" if prob >= 0.5 else "Safe / Likely genuine",
                "top_features": matches,
                "model_engine": "Heuristic Fallback"
            }

        try:
            # Predict probability: class 0 = Genuine, class 1 = Scam
            prob_scam = float(self.model.predict_proba([text])[0][1])
            is_scam = prob_scam >= 0.50
            confidence = round(max(prob_scam, 1.0 - prob_scam) * 100, 1)

            # Extract top indicative features present in the query
            vectorizer = self.model.named_steps["tfidf"]
            classifier = self.model.named_steps["clf"]
            feature_names = vectorizer.get_feature_names_out()
            coefs = classifier.coef_[0]

            query_vec = vectorizer.transform([text]).toarray()[0]
            top_words = []
            for idx in np.where(query_vec > 0)[0]:
                if coefs[idx] > 0.3:  # Positive coefficient indicates scam correlation
                    top_words.append((feature_names[idx], round(float(coefs[idx]), 2)))

            # Sort by highest scam correlation
            top_words.sort(key=lambda x: x[1], reverse=True)
            top_features_list = [f"{w} (+{c})" for w, c in top_words[:5]]

            return {
                "is_scam": is_scam,
                "scam_probability": round(prob_scam, 3),
                "confidence_pct": confidence,
                "verdict": "High scam probability" if is_scam else "Safe / Likely genuine",
                "top_features": top_features_list,
                "dataset_source": self.dataset_source,
                "model_engine": "TF-IDF + Logistic Regression"
            }
        except Exception as e:
            print(f"[ML MODEL] Prediction error: {e}")
            return {
                "is_scam": False,
                "scam_probability": 0.5,
                "confidence_pct": 50.0,
                "verdict": "Analysis Inconclusive",
                "top_features": []
            }

    def get_info(self) -> Dict[str, Any]:
        """Returns metadata about the active ML model."""
        return {
            "is_trained": self.is_trained,
            "dataset_source": self.dataset_source,
            "train_samples_count": self.train_samples_count,
            "engine": "Scikit-Learn (TF-IDF + Logistic Regression)"
        }


# Global ML model instance initialized on module load
scam_classifier = ScamClassifier()
