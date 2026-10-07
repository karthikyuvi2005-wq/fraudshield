# 🛡️ FraudShield: AI-Powered Multi-Vector Cyber Fraud & Phishing Defense Platform

FraudShield is an enterprise-grade cyber defense and proactive fraud prevention system. It inspects communications across multiple threat vectors—including SMS/WhatsApp phishing (smishing), deceptive URLs, coercive cyber blackmail/sextortion, digital arrest impersonation scams, and credential harvesting.

---

## 🚀 Key Features

- **Multi-Vector Risk Engine**: Combines statistical Machine Learning (TF-IDF + Logistic Regression, URL Random Forest) with deterministic heuristic rule interceptors.
- **Credential Harvesting Shield**: Intercepts requests soliciting Credit/Debit Card numbers, ATM PINs, UPI PINs, CVVs, and OTPs while preserving legitimate educational advisories.
- **Cyber Blackmail & Sextortion Interception**: Immediate detection of coercive threats, webcam extortion, and non-consensual media demands.
- **Psychological Manipulation Meter**: Quantifies cognitive coercion across 4 vectors: **Urgency**, **Fear**, **Reward**, and **Authority**.
- **Explainable AI (XAI)**: Integrated **SHAP (SHapley Additive exPlanations)** and token-level attribution showing exact factors driving the risk score.
- **Universal Image & OCR Analyzer**: Extracts and audits text and QR codes from screenshots and payment flyers.
- **Active URL Sandbox**: Inspects live web page metadata, redirect trails, domain homoglyphs, Punycode, and suspicious TLDs.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn
- **Machine Learning & Explainability**: Scikit-learn, SHAP, Joblib, Pandas, NumPy
- **Image Processing**: OpenCV, Pillow (PIL)
- **Database**: SQLite3 (Local Incident Logging & Threat Audit)
- **Frontend**: Responsive Single-Page Web Dashboard (Vanilla JS, CSS3, HTML5)

---

## 💻 Local Setup & Execution

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/fraudshield.git
   cd fraudshield
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the Web Dashboard**:
   Open your browser and visit: `http://127.0.0.1:8000`

---

## 🌐 Cloud Deployment

- **Start Command**: `uvicorn app.py:app --host 0.0.0.0 --port $PORT` or `python app.py`
- Ready for one-click deployment on **Render**, **Railway**, or **Koyeb**.
