import os
import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix

# =====================================================================
# 1. ENRICHED LEXICAL & STRUCTURAL FEATURE EXTRACTOR
# =====================================================================
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "bank", "secure", "account", "wallet",
    "kyc", "otp", "free", "bonus", "claim", "prize", "support", "password",
    "signin", "confirm", "security", "cgi-bin", "banking", "authenticate",
    "wp-content", "admin", "paypal", "appleid"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "cutt.ly", "rb.gy", "is.gd"
]

def extract_url_features(url: str) -> dict:
    """Extract 16 lexical and structural security features from a URL."""
    u = str(url).strip()
    u_scheme = u if u.startswith(("http://", "https://")) else ("http://" + u)

    try:
        parsed = urlparse(u_scheme)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        netloc, path = "", ""

    u_len = len(u)
    d_len = len(netloc)
    p_len = len(path)
    digits = sum(c.isdigit() for c in u)
    subdomains = max(0, len(netloc.split(":")[0].split(".")) - 2) if "." in netloc else 0

    return {
        "url_len": u_len,
        "domain_len": d_len,
        "path_len": p_len,
        "has_ip": 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", netloc) else 0,
        "count_dots": u.count("."),
        "count_hyphens": u.count("-"),
        "count_at": u.count("@"),
        "count_slash": u.count("/"),
        "count_question": u.count("?"),
        "count_equal": u.count("="),
        "count_percent": u.count("%"),
        "count_digits": digits,
        "digit_ratio": round(digits / max(1, u_len), 3),
        "num_subdomains": subdomains,
        "is_shortened": 1 if any(s in netloc for s in SHORTENER_DOMAINS) else 0,
        "suspicious_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in u.lower())
    }

def train_url_model():
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)

    # 1. Load Kaggle Benchmark Dataset
    kaggle_csv = "phishing_site_urls.csv"
    if os.path.exists(kaggle_csv):
        print(f"Loading Kaggle benchmark from '{kaggle_csv}'...")
        df_raw = pd.read_csv(kaggle_csv)
        df_raw["label"] = df_raw["Label"].map({"good": 0, "bad": 1})
        df_raw = df_raw.rename(columns={"URL": "url"})[["url", "label"]].dropna()

        # Stratified representative sample of 30,000 URLs (15k good, 15k bad)
        sample = df_raw.groupby("label").sample(n=15000, random_state=42).reset_index(drop=True)
        sample.to_csv("data/clean_urls.csv", index=False)
        print(f"Sampled 30,000 balanced benchmark URLs (15,000 Good / 15,000 Bad) to 'data/clean_urls.csv'.")
        df_urls = sample
    else:
        print("Fallback: Using existing 'data/clean_urls.csv'...")
        df_urls = pd.read_csv("data/clean_urls.csv")

    # 2. Extract Features
    print("Extracting 16 lexical and structural features from URLs...")
    features_list = [extract_url_features(u) for u in df_urls["url"]]
    X = pd.DataFrame(features_list)
    y = df_urls["label"]

    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. Train Random Forest Model
    print(f"Training Random Forest classifier on {len(X_train)} samples...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=16, n_jobs=-1, random_state=42)
    rf_model.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = rf_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("=" * 60)
    print("[SUCCESS] STEP 4 COMPLETE: KAGGLE RANDOM FOREST MODEL TRAINED")
    print("=" * 60)
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%")
    print("\nConfusion Matrix (6,000 test URLs):")
    print(f"  True Legitimate caught: {cm[0][0]}")
    print(f"  False Alarms          : {cm[0][1]}")
    print(f"  Missed Phishing       : {cm[1][0]}")
    print(f"  Phishing caught!      : {cm[1][1]}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # 6. Save Model Artifacts
    joblib.dump(rf_model, "models/url_classifier.pkl")
    joblib.dump(list(X.columns), "models/url_feature_names.pkl")
    print("Saved artifacts: 'models/url_classifier.pkl' and 'models/url_feature_names.pkl'")

if __name__ == "__main__":
    train_url_model()
