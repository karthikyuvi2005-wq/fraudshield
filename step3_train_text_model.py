import os
import joblib
import pandas as pd
import nbformat as nbf
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score

# 1. Load cleaned dataset from Step 2
df = pd.read_csv("data/clean_sms.csv")

# 2. Stratified train/test split (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    df["text"],
    df["label"],
    test_size=0.20,
    random_state=42,
    stratify=df["label"]
)

# 3. TF-IDF Feature Extraction
# Using unigrams + bigrams ('urgent', 'urgent notice')
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=4000,
    sublinear_tf=True,
    stop_words="english"
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# 4. Train Logistic Regression model with balanced class weights
# Balanced class weight is critical because fraud is only ~12.6% of data
model = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
model.fit(X_train_vec, y_train)

# 5. Model Evaluation
y_pred = model.predict(X_test_vec)
acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print("=" * 55)
print("[SUCCESS] STEP 3 COMPLETE: TEXT MODEL TRAINED")
print("=" * 55)
print(f"Accuracy  : {acc * 100:.2f}%")
print(f"F1-Score  : {f1 * 100:.2f}%")
print("\nConfusion Matrix (Test set of 1,034 samples):")
print(f"  True Negatives (Safe correctly identified)  : {cm[0][0]}")
print(f"  False Positives (Safe wrongly flagged)      : {cm[0][1]}")
print(f"  False Negatives (Fraud missed)              : {cm[1][0]}")
print(f"  True Positives (Fraud caught!)              : {cm[1][1]}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Fraud"]))

# 6. Save artifacts to models/ directory
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/text_classifier.pkl")
joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
print("Saved artifacts: 'models/text_classifier.pkl' and 'models/tfidf_vectorizer.pkl'")

# 7. Quick Smoke Test with realistic examples
print("-" * 55)
print("Live Model Inference Test:")
test_samples = [
    "Hey dad, can you pick up milk and bread on your way home?",
    "URGENT: Your bank account will be locked within 24h. Click http://bank-kyc-verify.xyz to update PAN card immediately.",
    "Congratulations! You won 1,000,000 lottery cash prize. Call 0871234567 to claim your prize now."
]
test_vec = vectorizer.transform(test_samples)
preds = model.predict(test_vec)
probs = model.predict_proba(test_vec)

for text, pred, prob in zip(test_samples, preds, probs):
    fraud_prob = prob[1] * 100
    tag = "FRAUD" if pred == 1 else "SAFE "
    print(f"[{tag}] ({fraud_prob:5.1f}% risk) -> {text[:65]}...")
print("=" * 55)

# 8. Note: Notebook is maintained via update_notebook.py
print("Text model artifacts updated successfully in models/ directory.")
