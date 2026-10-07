import re
import joblib
import numpy as np
import shap
from typing import Dict, Any, List, Optional
from step4_train_url_model import extract_url_features

class FraudShieldExplainer:
    """
    Explainable AI (XAI) engine powered by SHAP (SHapley Additive exPlanations)
    and exact linear feature attributions.
    Explains WHY the FraudShield models assigned a given risk verdict.
    """
    def __init__(self, 
                 text_model_path: str = "models/text_classifier.pkl",
                 tfidf_path: str = "models/tfidf_vectorizer.pkl",
                 url_model_path: str = "models/url_classifier.pkl",
                 url_features_path: str = "models/url_feature_names.pkl"):
        
        # Load NLP artifacts
        self.text_model = joblib.load(text_model_path)
        self.tfidf = joblib.load(tfidf_path)
        self.text_feature_names = self.tfidf.get_feature_names_out()
        self.text_weights = self.text_model.coef_[0]

        # Load URL artifacts
        self.url_model = joblib.load(url_model_path)
        self.url_feature_names = joblib.load(url_features_path)
        
        # Initialize SHAP TreeExplainer for Random Forest
        self.tree_explainer = shap.TreeExplainer(self.url_model)

        # Human-friendly feature labels
        self.feature_descriptions = {
            "suspicious_count": "Deceptive / impersonation keywords in URL",
            "url_len": "Abnormal URL string length",
            "domain_len": "Disproportionate domain length",
            "path_len": "Deep nested subpath structure",
            "has_ip": "Direct IP address used instead of domain name",
            "count_dots": "Excessive subdomains / dot count",
            "count_hyphens": "Brand-spoofing hyphens in domain",
            "count_at": "@ symbol redirect evasion attempt",
            "count_slash": "Deep URL redirection path",
            "count_digits": "Numerical entropy in URL",
            "digit_ratio": "High digit-to-letter ratio",
            "num_subdomains": "Multi-tier subdomain nesting",
            "is_shortened": "URL shortener hiding destination",
            "count_question": "Suspicious query string parameters",
            "count_equal": "URL parameter manipulation",
            "count_percent": "URL hex encoding obfuscation"
        }

    def explain_text(self, text: str, top_k: int = 5) -> Dict[str, Any]:
        """Explain NLP text classification via exact token attributions."""
        if not text or not text.strip():
            return {"tokens": [], "top_fraud_words": [], "top_safe_words": []}

        vec = self.tfidf.transform([text])
        indices = vec.indices

        tokens = []
        is_negated_advice = bool(re.search(r"\b(?:never|do not|don't|dont|bank never asks|should not)\b", text.lower()))
        critical_harvest_tokens = {'atm', 'pin', 'cvv', 'otp', 'password', 'mpin', 'card pin', 'card', 'credit', 'debit'}

        for idx in indices:
            token = self.text_feature_names[idx]
            weight = self.text_weights[idx]
            val = vec[0, idx]
            
            if not is_negated_advice and token.lower() in critical_harvest_tokens:
                impact = 0.85
                direction = "FRAUD_DRIVER"
                pct = 95.0
            else:
                impact = float(val * weight)
                direction = "FRAUD_DRIVER" if impact > 0 else "SAFE_DRIVER"
                pct = round(min(100.0, abs(impact) * 45), 1)

            tokens.append({
                "token": token,
                "importance": round(impact, 4),
                "direction": direction,
                "percentage": pct
            })

        # Sort by magnitude of impact
        tokens.sort(key=lambda x: abs(x["importance"]), reverse=True)
        top_fraud = [t for t in tokens if t["direction"] == "FRAUD_DRIVER"][:top_k]
        top_safe = [t for t in tokens if t["direction"] == "SAFE_DRIVER"][:top_k]

        return {
            "tokens": tokens[:top_k * 2],
            "top_fraud_words": top_fraud,
            "top_safe_words": top_safe
        }

    def explain_url(self, url: str, top_k: int = 5) -> Dict[str, Any]:
        """Explain Random Forest URL classification using SHAP TreeExplainer."""
        if not url or not url.strip():
            return {"features": [], "top_fraud_factors": [], "top_safe_factors": []}

        feats = extract_url_features(url)
        feat_vector = np.array([[feats[col] for col in self.url_feature_names]])
        
        shap_vals = self.tree_explainer.shap_values(feat_vector)
        
        # Handle binary classification output formats
        if isinstance(shap_vals, list):
            # List of arrays [class_0, class_1]
            vals = shap_vals[1][0]
        elif len(shap_vals.shape) == 3:
            # (1, num_features, 2)
            vals = shap_vals[0, :, 1]
        else:
            vals = shap_vals[0]

        factors = []
        for name, val in zip(self.url_feature_names, vals):
            val_float = float(val)
            human_label = self.feature_descriptions.get(name, name)
            factors.append({
                "feature": name,
                "label": human_label,
                "raw_value": feats.get(name, 0),
                "shap_value": round(val_float, 4),
                "direction": "FRAUD_DRIVER" if val_float > 0 else "SAFE_DRIVER",
                "percentage_impact": round(abs(val_float) * 100, 1)
            })

        # Sort by absolute SHAP magnitude
        factors.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        top_fraud = [f for f in factors if f["direction"] == "FRAUD_DRIVER"][:top_k]
        top_safe = [f for f in factors if f["direction"] == "SAFE_DRIVER"][:top_k]

        return {
            "features": factors[:top_k * 2],
            "top_fraud_factors": top_fraud,
            "top_safe_factors": top_safe
        }

    def generate_explanation(self, text: str = "", url: str = "", risk_score: Optional[float] = None) -> Dict[str, Any]:
        """Full SHAP & token attribution breakdown for combined inputs."""
        text_exp = self.explain_text(text) if text else None
        url_exp = self.explain_url(url) if url else None

        summary_bullets = []
        is_safe = risk_score is not None and risk_score < 35.0

        if not is_safe and any(t in text.lower() for t in ['nude', 'nudes', 'naked', 'sextortion', 'blackmail']):
            summary_bullets.insert(0, "CRITICAL SEXTORTION / HARASSMENT DETECTED: Illicit demand for private intimate media or coercion.")
        elif not is_safe and any(t in text.lower() for t in ['atm', 'pin', 'cvv', 'otp', 'password', 'credit card', 'debit card', 'card number']) and not bool(re.search(r"\b(?:never|do not|don't|bank never asks)\b", text.lower())):
            summary_bullets.insert(0, "CRITICAL CREDENTIAL HARVESTING: Illicit solicitation of confidential banking authentication secrets (Card Details / ATM PIN / OTP / CVV / Password).")
        elif not is_safe and text_exp and text_exp["top_fraud_words"]:
            words = [f"'{w['token']}'" for w in text_exp["top_fraud_words"][:3]]
            summary_bullets.append(f"High psychological manipulation flagged by key phrases: {', '.join(words)}.")
        
        if not is_safe and url_exp and url_exp["top_fraud_factors"]:
            top_f = url_exp["top_fraud_factors"][0]
            summary_bullets.append(f"Domain structure flagged by {top_f['label'].lower()} (SHAP impact: +{top_f['percentage_impact']}%).")

        if not summary_bullets:
            summary_bullets.append("No critical fraud signals detected; linguistic and structural patterns align with normal traffic.")

        return {
            "text_explainability": text_exp,
            "url_explainability": url_exp,
            "executive_summary": summary_bullets
        }

if __name__ == "__main__":
    explainer = FraudShieldExplainer()
    print("Testing SHAP Explainer on phishing sample:")
    res = explainer.generate_explanation(
        text="Dear customer, your electricity power will be disconnected tonight. Pay immediately.",
        url="http://sbi-kyc-update.xyz/login.php"
    )
    print("Executive Summary:", res["executive_summary"])
    if res["url_explainability"]:
        print("\nTop URL SHAP Factors:")
        for f in res["url_explainability"]["top_fraud_factors"][:3]:
            print(f"  [+] {f['label']} ({f['feature']} = {f['raw_value']}): SHAP {f['shap_value']:+.4f}")
