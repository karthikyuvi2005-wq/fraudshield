import os
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import joblib
import pandas as pd
from step4_train_url_model import extract_url_features
from page_inspector import safe_inspect_page
from explainability import FraudShieldExplainer

OFFICIAL_DOMAINS = {
    'google': ['google.com', 'google.co.in', 'youtube.com', 'gmail.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
    'hdfc': ['hdfcbank.com'],
    'icici': ['icicibank.com'],
    'axis': ['axisbank.com'],
    'kotak': ['kotak.com'],
    'pnb': ['pnbindia.in'],
    'bankofbaroda': ['bankofbaroda.in'],
    'canara': ['canarabank.com'],
    'paytm': ['paytm.com'],
    'phonepe': ['phonepe.com'],
    'bhim': ['bhimupi.org.in'],
    'razorpay': ['razorpay.com'],
    'irctc': ['irctc.co.in'],
    'gov': ['gov.in', 'nic.in'],
    'cybercrime': ['cybercrime.gov.in'],
    'rbi': ['rbi.org.in'],
    'uidai': ['uidai.gov.in'],
    'incometax': ['incometax.gov.in'],
    'indiapost': ['indiapost.gov.in'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com'],
    'netflix': ['netflix.com'],
    'whatsapp': ['whatsapp.com'],
    'telegram': ['telegram.org', 't.me'],
    'wikipedia': ['wikipedia.org', 'wikimedia.org'],
    'github': ['github.com', 'github.io'],
    'stackoverflow': ['stackoverflow.com']
}

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.buzz', '.club', '.online', '.site', '.vip', '.work',
    '.icu', '.tk', '.ml', '.cf', '.gq', '.cc', '.info', '.biz', '.rest',
    '.click', '.link', '.live', '.shop', '.tokyo', '.fit', '.gdn', '.loan',
    '.men', '.stream', '.trade', '.win', '.party', '.bid'
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy'}

def is_valid_url(url: str) -> bool:
    """
    Validates whether an input string is genuinely a URL or web domain.
    Filters out plain words, random sentences, search terms, and gibberish.
    """
    u = str(url).strip()
    if not u or " " in u:
        return False

    test_u = u if u.startswith(("http://", "https://", "ftp://")) else ("https://" + u)
    try:
        parsed = urlparse(test_u)
        netloc = parsed.netloc.split(":")[0]
        if not netloc:
            return False

        # Valid IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc):
            return True

        # Valid domain with recognizable TLD
        if "." in netloc:
            parts = netloc.split(".")
            tld = parts[-1]
            if len(tld) >= 2 and tld.isalpha() and all(len(p) > 0 for p in parts):
                return True

        return False
    except Exception:
        return False

class FraudShieldRiskEngine:
    """
    Core Decision & Scoring Engine for FraudShield AI.
    Combines:
    1. TF-IDF + Logistic Regression NLP Text Model
    2. Multi-Layer URL Defense (Validation + Whitelist + Brand Protection + Kaggle Random Forest ML)
    3. Live Sandbox Active Inspection (Headless DOM analysis for password/OTP harvesting & title spoofing)
    4. Psychological Manipulation Meter (Urgency, Fear, Reward, Authority)
    5. Threat Taxonomy (KYC, Utility Bill, Digital Arrest, Job Tasks)
    6. Citizen Safe Action Protocols (1930 Helpline)
    """
    def __init__(self, text_model_path=None,
                 vectorizer_path=None,
                 url_model_path=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        def get_model_file(fname):
            for candidate in [
                os.path.join(base_dir, "models", fname),
                os.path.join(base_dir, "models", "models", fname),
                os.path.join(base_dir, fname)
            ]:
                if os.path.exists(candidate):
                    return candidate
            return os.path.join(base_dir, "models", fname)

        text_model_path = text_model_path or get_model_file("text_classifier.pkl")
        vectorizer_path = vectorizer_path or get_model_file("tfidf_vectorizer.pkl")
        url_model_path = url_model_path or get_model_file("url_classifier.pkl")

        try:
            self.text_model = joblib.load(text_model_path)
            self.vectorizer = joblib.load(vectorizer_path)
        except Exception as e:
            print(f"[FraudShield] NLP model artifacts notice: {e}. Operating in heuristic fallback mode.")
            self.text_model = None
            self.vectorizer = None

        try:
            self.url_model = joblib.load(url_model_path)
        except Exception as e:
            print(f"[FraudShield] URL model artifact notice: {e}. Operating in heuristic fallback mode.")
            self.url_model = None

        try:
            self.explainer = FraudShieldExplainer(
                text_model_path=text_model_path,
                tfidf_path=vectorizer_path,
                url_model_path=url_model_path
            )
        except Exception as e:
            print(f"[FraudShield] Explainer notice: {e}")
            self.explainer = None

        # Manipulation Meter Lexicons (English + Hinglish Social Engineering)
        self.manipulation_lexicon = {
            "urgency": [
                r"\burgent(?:ly)?\b", r"\bimmediat(?:e|ely)\b", r"\bwithin \d+\s*(?:hours|hrs|mins|minutes)\b",
                r"\bact now\b", r"\bhurry\b", r"\btoday only\b", r"\bexpires?\b", r"\baction required\b",
                r"\blast chance\b", r"\binstant(?:ly)?\b", r"\bpromptly\b", r"\balert\b", r"\bwarning\b",
                r"\bbefore (?:tonight|it is too late|\d+)\b", r"\btime running out\b", r"\bdeadline\b",
                r"\bturant\b", r"\bjaldi\b", r"\baaj hi\b", r"\babhi call karein\b", r"\baaj raat \d+\b"
            ],
            "fear": [
                r"\bhack(?:ed|ing|er|ers)?\b", r"\bbreach(?:ed)?\b", r"\bcompromis(?:ed|ing)\b",
                r"\bunauthorized\b", r"\bunusual (?:activity|login|sign[- ]in|transaction)\b",
                r"\bleak(?:ed)?\b", r"\bstolen\b", r"\bmalware\b", r"\bvirus\b", r"\bransomware\b",
                r"\binfect(?:ed)?\b", r"\bblock(?:ed)?\b", r"\bsuspend(?:ed)?\b", r"\barrest(?:ed)?\b",
                r"\bpolice\b", r"\bfir\b", r"\bcourt\b", r"\bpenalty\b", r"\bfrozen\b", r"\bfreeze\b",
                r"\bdeactivat(?:ed)?\b", r"\blegal action\b", r"\bwarning\b", r"\bseized?\b",
                r"\bcbi\b", r"\bed\b", r"\bnarcotics?\b", r"\bextort(?:ion)?\b", r"\bblackmail\b",
                r"\bbijli kat\b", r"\blight kat\b", r"\bpower cut\b", r"\bkhata band\b", r"\bkhata block\b",
                r"\bjail\b", r"\bpolice aayegi\b", r"\bwarrant nikla\b", r"\bjurmana\b", r"\baadhaar block\b"
            ],
            "reward": [
                r"\blottery\b", r"\bwon\b", r"\bwinner\b", r"\bprize\b", r"\bcashback\b",
                r"\bcrore\b", r"\blakh\b", r"\bbonus\b", r"\bfree\b", r"\bgift\b",
                r"\bclaim(?: now)?\b", r"\breward\b", r"\bjackpot\b", r"\bearn \d+\b", r"\bairdrop\b",
                r"\bghar baithe kamaye\b", r"\bpaise jeete\b", r"\binaam\b", r"\blottery lagi\b", r"\broz kamaye\b"
            ],
            "authority": [
                r"\bbank(?:ing)?\b", r"\brbi\b", r"\bincome tax\b", r"\bgst\b", r"\bcustoms\b",
                r"\bsbi\b", r"\bhdfc\b", r"\bicici\b", r"\baxis\b", r"\bpaytm\b", r"\bphonepe\b",
                r"\belectricity (?:officer|board|department)\b", r"\bdepartment\b", r"\bofficial\b",
                r"\btelecom\b", r"\btrai\b", r"\bgov(?:ernment)?\b", r"\bcyber (?:crime|cell)\b",
                r"\bfraud (?:prevention|department|cell)\b", r"\bsecurity (?:team|cell|alert)\b",
                r"\badhikari\b", r"\bbijli vibhag\b", r"\bvidyut vibhag\b", r"\bpolice thana\b", r"\bsarkari\b"
            ]
        }

        # Scam Taxonomy Patterns (India & Global threats)
        self.scam_patterns = {
            "Security Breach / Account Takeover Scare": [
                r"\bhack(?:ed|ing|er)?\b", r"\bbreach\b", r"\bcompromis(?:ed)?\b",
                r"\bunauthorized\b", r"\bvirus detected\b", r"\bmalware detected\b",
                r"\bpassword leaked\b", r"\bsecurity alert\b", r"\baccount takeover\b"
            ],
            "KYC / Banking Phishing": [
                r"\bkyc\b", r"\bpan card\b", r"\baadhaar\b", r"\baccount (?:blocked|suspended|frozen)\b",
                r"\bnetbanking\b", r"\bupdate details\b", r"\bdebit card expiry\b", r"\bunfreeze\b",
                r"\bkhata (?:block|band)\b", r"\bpan link\b", r"\baadhaar verify\b"
            ],
            "Digital Arrest / Extortion": [
                r"\bdigital arrest\b", r"\bparcel seized\b", r"\bdrugs found\b", r"\bcustoms\b",
                r"\bcbi warrant\b", r"\bpolice verification\b", r"\bskype interrogation\b",
                r"\baadhaar (?:pe|par) (?:case|warrant)\b", r"\bpolice aayegi\b", r"\bjail hogi\b"
            ],
            "Electricity / Utility Bill Scam": [
                r"\belectricity (?:bill|power|connection)\b", r"\bpower (?:cut|disconnect)\b",
                r"\bbill overdue\b", r"\belectricity officer\b",
                r"\bbijli (?:kat|bill)\b", r"\blight (?:kat|cut)\b", r"\bvidyut vibhag\b"
            ],
            "Part-Time Job / Task Scam": [
                r"\bpart time job\b", r"\bearn \d+ daily\b", r"\blike youtube videos\b",
                r"\btelegram task\b", r"\bwork from home\b", r"\bdaily salary\b",
                r"\bghar baithe kamaye\b", r"\broz \d+ kamaye\b"
            ],
            "Lottery / Prize Scam": [
                r"\bcongratulations\b", r"\bkbc lottery\b", r"\blucky draw\b",
                r"\bclaim prize\b", r"\bwon cash\b", r"\bpaise jeete\b", r"\blottery lagi\b"
            ],
            "Loan / Credit Scam": [
                r"\binstant loan\b", r"\bzero interest\b", r"\bpre-approved loan\b",
                r"\bloan without cibil\b", r"\bturant loan\b"
            ]
        }

    def evaluate_url(self, raw_url: str) -> Dict[str, Any]:
        """Multi-layer URL Threat Evaluation with syntax validation."""
        url = str(raw_url).strip()
        if not url:
            return {"risk_score": 0.0, "is_valid": False, "is_official": False, "flags": []}

        # 1. Syntax Validation: check if it's genuinely a URL/domain
        if not is_valid_url(url):
            return {
                "risk_score": 0.0,
                "is_valid": False,
                "is_official": False,
                "flags": ["Note: Input is plain text or words, not a valid web URL/domain. URL threat scan skipped."]
            }

        # 2. Normalization
        has_explicit_scheme = url.startswith(("http://", "https://"))
        normalized_url = url if has_explicit_scheme else ("https://" + url)

        try:
            parsed = urlparse(normalized_url)
            netloc = parsed.netloc.lower().split(":")[0]
        except Exception:
            netloc = ""

        # 3. Whitelist Check (Official Banks, Gov portals, Tech giants)
        for brand, valids in OFFICIAL_DOMAINS.items():
            for v in valids:
                if netloc == v or netloc.endswith("." + v):
                    return {
                        "risk_score": 1.0,
                        "is_valid": True,
                        "is_official": True,
                        "flags": [f"Verified official domain for {brand.upper()}"]
                    }

        flags = []
        rule_risk = 0.0

        # 4. Check for raw IP address
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc))
        if is_ip:
            rule_risk += 65.0
            flags.append("Host is a raw IP address (phishers use raw IPs to bypass domain registry checks)")

        # 5. Check for Punycode / Internationalized domain (Homoglyph evasion)
        if "xn--" in netloc:
            rule_risk = max(rule_risk, 76.0)
            flags.append("Punycode / Internationalized domain detected (frequently abused in homoglyph lookalike attacks)")

        # 6. Check for Character-Substitution Lookalike Homoglyphs (0->o, 1->l, @->a, 3->e)
        homoglyph_map = str.maketrans({'0': 'o', '1': 'l', '@': 'a', '$': 's', '3': 'e'})
        normalized_netloc = netloc.translate(homoglyph_map)
        for brand in ['sbi', 'onlinesbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe', 'google', 'amazon', 'netflix', 'paypal']:
            if brand in normalized_netloc and brand not in netloc:
                rule_risk = max(rule_risk, 72.0)
                flags.append(f"Lookalike / Homoglyph domain spoofing legitimate brand '{brand.upper()}' ({netloc})")
                break

        # 7. Check for high-risk cheap/disposable TLDs
        for tld in SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                rule_risk += 40.0
                flags.append(f"Uses high-risk/disposable TLD ({tld}) frequently abused in phishing")
                break

        # 8. Check for URL shorteners (masking destination)
        if any(s in netloc for s in SHORTENERS):
            rule_risk += 50.0
            flags.append("Masked URL shortener (hides true target destination)")

        # 9. Check for Brand Impersonation & Brand Squatting Action Combos
        action_keywords = ['kyc', 'login', 'verify', 'update', 'secure', 'portal', 'auth', 'support', 'help', 'alert', 'refund', 'card', 'pan', 'aadhaar', 'claim', 'gift']
        for brand in OFFICIAL_DOMAINS.keys():
            if brand in netloc:
                has_action = any(ak in netloc for ak in action_keywords) or any(ak in parsed.path.lower() for ak in action_keywords)
                if has_action:
                    rule_risk = max(rule_risk, 88.0)
                    flags.append(f"Critical Brand Squatting: Domain combines brand '{brand.upper()}' with deceptive action keyword")
                else:
                    rule_risk = max(rule_risk, 55.0)
                    flags.append(f"Domain impersonates known brand '{brand.upper()}' on unofficial host ({netloc})")
                break

        # 10. Check for Credential Harvesting / Phishing Script Paths
        phish_paths = ['/login.php', '/verify.php', '/kyc.php', '/update.php', '/netbanking', '/signin', '/auth.php', '/apk/']
        if any(pp in parsed.path.lower() for pp in phish_paths):
            rule_risk = max(rule_risk, 65.0)
            flags.append(f"Credential harvest or phishing script path detected in URL: {parsed.path}")

        # 11. Check for Excessive Subdomain Nesting
        subdomains = [p for p in netloc.split('.') if p]
        if len(subdomains) >= 4 and not netloc.endswith('.gov.in') and not netloc.endswith('.co.in'):
            rule_risk += 35.0
            flags.append(f"Excessive subdomain nesting ({len(subdomains)} tiers) used to mask authentic origin")

        # 12. ML Model Prediction on Kaggle-trained Random Forest
        if self.url_model is not None:
            features = pd.DataFrame([extract_url_features(normalized_url)])
            ml_prob = self.url_model.predict_proba(features)[0][1]
            ml_risk = float(ml_prob * 100)
        else:
            ml_risk = rule_risk

        # 13. Ensemble Hybrid Fusion
        if flags:
            final_risk = min(100.0, max(ml_risk, rule_risk))
        else:
            final_risk = ml_risk

        return {
            "risk_score": round(final_risk, 1),
            "is_valid": True,
            "is_official": False,
            "flags": flags
        }

    def _extract_manipulation_meter(self, text: str) -> Dict[str, int]:
        """Calculates 0-100 score for Urgency, Fear, Reward, and Authority."""
        text_lower = text.lower()
        meter = {}
        for category, patterns in self.manipulation_lexicon.items():
            matches = sum(len(re.findall(p, text_lower)) for p in patterns)
            score = min(100, matches * 35)
            meter[category] = score
        return meter

    def _classify_scam_type(self, text: str, url: str) -> str:
        """Determines the specific scam category using pattern heuristics."""
        combined = f"{text} {url}".lower()
        for category, patterns in self.scam_patterns.items():
            for p in patterns:
                if re.search(p, combined):
                    return category
        return "Generic Suspicious / Unclassified"

    def evaluate_text(self, raw_text: str) -> Dict[str, Any]:
        """
        Multi-Layer Text Threat Evaluation:
        1. NLP Statistical Model (TF-IDF + Logistic Regression)
        2. Threat Pattern & Social Engineering Heuristic Engine:
           - Security Breach & Hack Panic Vector ("bank is hacked", "account compromised")
           - Banking / KYC Suspension Traps ("account blocked", "card suspended", "verify kyc")
           - Digital Arrest & Extortion ("cbi warrant", "digital arrest", "drugs found")
           - Utility Cut Scares ("electricity disconnected", "power cut")
           - Prize / Lottery Scams ("kbc lottery", "won prize")
        3. Psychological Manipulation Scoring (Urgency, Fear, Reward, Authority)
        4. Normal / Legitimate Conversational Safeguard
        5. Hybrid Fusion (combines statistical NLP with deterministic cyber threat heuristics)
        """
        text = str(raw_text).strip()
        if not text:
            return {
                "risk_score": 0.0,
                "flags": [],
                "manipulation_meter": {"urgency": 0, "fear": 0, "reward": 0, "authority": 0},
                "scam_type": "Legitimate / None"
            }

        text_lower = text.lower()

        # 1. Statistical ML Model Score
        if self.text_model is not None and self.vectorizer is not None:
            text_vec = self.vectorizer.transform([text])
            ml_prob = float(self.text_model.predict_proba(text_vec)[0][1] * 100)
        else:
            ml_prob = 0.0

        # 2. Manipulation Meter Extraction
        manipulation_meter = self._extract_manipulation_meter(text)

        # 3. Deterministic Threat Patterns & Flags
        flags = []
        rule_risk = 0.0
        detected_scam_type = None

        # --- VECTOR A: Security Breach & Hack Scare (Highest Coercion) ---
        hack_breach_patterns = [
            r"\b(?:bank|account|system|wallet|card|phone|device|credentials?|server)\s+(?:is\s+|are\s+|has been\s+|was\s+)?(?:hacked|compromised|breached|leaked|infected)\b",
            r"\b(?:bank is hacked|account is hacked|system is hacked|phone is hacked)\b",
            r"\b(?:hacked|hacker|hacking)\b",
            r"\b(?:security breach|breach alert|unauthorized (?:access|login|sign[- ]in|transaction|withdrawal))\b",
            r"\b(?:unusual|suspicious)\s+(?:activity|login|sign[- ]in|transaction|attempt)\b",
            r"\b(?:someone logged into|accessed your|breached your)\s+(?:account|device|bank)\b",
            r"\b(?:malware|trojan|virus|ransomware|spyware)\s+(?:detected|found|infected)\b",
            r"\b(?:funds|money|balance)\s+(?:transferred without|deducted without|at risk|stolen)\b"
        ]
        if any(re.search(p, text_lower) for p in hack_breach_patterns):
            rule_risk = max(rule_risk, 82.0)
            flags.append("SECURITY BREACH / HACK PANIC: Message claims systems or accounts are hacked/breached to trigger panic")
            detected_scam_type = "Security Breach / Account Takeover Scare"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 75)
            manipulation_meter["authority"] = max(manipulation_meter["authority"], 40)

        # --- VECTOR B: Digital Arrest & Law Enforcement Extortion ---
        digital_arrest_patterns = [
            r"\b(?:digital arrest|cbi warrant|police warrant|cyber crime cell|interrogation|skype call|parcel seized|narcotics found|customs seized)\b",
            r"\b(?:arrest warrant|supreme court notice|non[- ]bailable warrant|ed summons)\b",
            r"\b(?:aadhaar (?:par|pe) (?:case|warrant|fir)|police aayegi|jail hogi|customs (?:ne|me) parcel pakda)\b"
        ]
        if any(re.search(p, text_lower) for p in digital_arrest_patterns):
            rule_risk = max(rule_risk, 88.0)
            flags.append("DIGITAL ARREST / LEGAL EXTORTION: Coercive impersonation of law enforcement, police, or CBI")
            detected_scam_type = "Digital Arrest / Extortion"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 85)
            manipulation_meter["authority"] = max(manipulation_meter["authority"], 75)

        # --- VECTOR C: Account Freeze & KYC Trap ---
        kyc_freeze_patterns = [
            r"\b(?:account|card|pan|kyc|sim|netbanking)\s+(?:is\s+|will be\s+|has been\s+)?(?:blocked|suspended|frozen|deactivated|restricted|terminated|locked)\b",
            r"\b(?:update|verify|link)\s+(?:kyc|pan card|aadhaar|debit card)\b",
            r"\b(?:pan|aadhaar)\s+(?:card\s+)?(?:not updated|verification required|expired)\b",
            r"\b(?:khata|account)\s+(?:block|band)\s+(?:ho gaya|ho jayega)\b",
            r"\b(?:pan card link karein|aadhaar verify karein|turant kyc karein)\b"
        ]
        if any(re.search(p, text_lower) for p in kyc_freeze_patterns):
            rule_risk = max(rule_risk, 76.0)
            flags.append("ACCOUNT FREEZE / KYC TRAP: Coercive warning that banking services or documents are blocked")
            detected_scam_type = detected_scam_type or "KYC / Banking Phishing"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 65)

        # --- VECTOR D: Electricity & Utility Cut Scare ---
        utility_patterns = [
            r"\b(?:electricity|power|gas|meter)\s+(?:will be\s+|is\s+)?(?:disconnected|cut off|terminated)\b",
            r"\b(?:bill overdue|contact officer|electricity officer)\b",
            r"\b(?:bijli|power|light|meter)\s+(?:kat jayegi|kat diya jayega|disconnect ho jayega|kaat di jayegi)\b",
            r"\b(?:bijli bill update|adhikari se baat karein|vidyut vibhag)\b"
        ]
        if any(re.search(p, text_lower) for p in utility_patterns):
            rule_risk = max(rule_risk, 72.0)
            flags.append("UTILITY CUT SCARE: Threatens power/electricity cut-off unless victim responds immediately")
            detected_scam_type = detected_scam_type or "Electricity / Utility Bill Scam"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 60)

        # --- VECTOR E: Lottery / Prize Fraud ---
        lottery_patterns = [
            r"\b(?:congratulations|won|winner|lottery|lucky draw|kbc|cashback)\s+(?:crore|lakh|prize|reward|won)\b",
            r"\b(?:won \d+|claim your prize|kbc lottery)\b",
            r"\b(?:paise jeete|lottery lagi|inaam mila)\b"
        ]
        if any(re.search(p, text_lower) for p in lottery_patterns):
            rule_risk = max(rule_risk, 74.0)
            flags.append("LOTTERY / PRIZE LURE: Deceptive prize or cash reward promise")
            detected_scam_type = detected_scam_type or "Lottery / Prize Scam"
            manipulation_meter["reward"] = max(manipulation_meter["reward"], 80)

        # --- VECTOR F: Part-Time Job & Task Scam ---
        job_patterns = [
            r"\b(?:part[- ]time job|work from home|earn \d+ daily|like youtube videos|telegram task|daily salary)\b",
            r"\b(?:earn (?:money|cash|rs|inr|\$) (?:daily|per day)|daily income)\b",
            r"\b(?:ghar baithe kamaye|roz \d+ kamaye|youtube video like karke paise|bina kisi investment)\b"
        ]
        if any(re.search(p, text_lower) for p in job_patterns):
            rule_risk = max(rule_risk, 68.0)
            flags.append("PART-TIME JOB / TASK SCAM: Unrealistic daily salary or task-based reward scheme")
            detected_scam_type = detected_scam_type or "Part-Time Job / Task Scam"
            manipulation_meter["reward"] = max(manipulation_meter["reward"], 70)

        # --- VECTOR G: Financial Credential & Secret Harvesting (Card Number, ATM PIN, OTP, CVV, Passwords) ---
        # Direct solicitation of Credit Card numbers, Debit Card details, ATM PIN, UPI PIN, CVV, OTP, or Passwords.
        req_verbs = r'(?:give|share|send|tell|enter|provide|ask(?:ing)? for|need|drop|disclose|what is|whats|can (?:you|u) (?:give|share|send|tell|provide)|can (?:i) (?:have|get)|submit|type|forward|bhejo|batao|do|de do)'
        cred_nouns = r'(?:(?:credit|debit|forex|atm|bank)\s*card(?:\s*(?:number|no|details|info|pin|cvv))?|card\s*(?:number|no|details|pin|cvv)|16\s*digit\s*(?:card\s*)?number|atm(?:\s*pin|\s*card)?|\bpin\b|\bpin\s*number\b|upi\s*pin|mpin|cvv|cvv2|cvc|\botp\b|one\s*time\s*password|(?:netbanking|login|banking|bank)\s*password|atm\s*code|\b4\s*digit\s*pin\b|\b6\s*digit\s*code\b|bank\s*account\s*(?:number|no|details))'

        pattern_req_cred = re.compile(rf'\b{req_verbs}\b(?:.*?\b(?:me|us|your|ur|the|my|apna)\b)?.*?\b{cred_nouns}\b', re.IGNORECASE)
        pattern_hinglish_cred = re.compile(rf'\b{cred_nouns}\b.*?\b(?:bhejo|batao|do|de do|karo|mang raha|manga|enter karo)\b', re.IGNORECASE)
        pattern_upi_receive = re.compile(r'\b(?:enter|put|type|share)\s+(?:upi\s+)?pin\s+(?:to\s+)?(?:receive|get|claim|accept|credit)\s+(?:money|cash|cashback|payment|amount|funds|prize)\b', re.IGNORECASE)
        
        advisory_negation = re.compile(
            r'\b(?:never|do not|don\'t|dont|should not|should never|must not|cannot|can\'t|cant|never share|never give|do not share|do not give|bank never asks|not to be shared|protect your|not|refuse|avoid|stop|without|mat|nahi|na)\b',
            re.IGNORECASE
        )
        negated_verb_pattern = re.compile(
            r'\b(?:not|never|don\'t|dont|do not|refuse|avoid|stop|without|mat)\s+(?:to\s+)?(?:give|giving|share|sharing|send|sending|tell|telling|enter|entering|provide|providing|disclose|disclosing|de|dena|bhejna|batana)\b',
            re.IGNORECASE
        )

        is_negated_advice = bool(negated_verb_pattern.search(text_lower)) or bool(advisory_negation.search(text_lower))
        is_credential_harvest = not is_negated_advice and (
            bool(pattern_req_cred.search(text_lower)) or
            bool(pattern_hinglish_cred.search(text_lower)) or
            bool(pattern_upi_receive.search(text_lower)) or
            bool(re.search(r'\b(?:give|share|send|tell)\s+(?:me\s+)?(?:your\s+|ur\s+)?(?:credit\s*card|debit\s*card|card|atm|pin|cvv|otp)\b', text_lower))
        )

        if is_credential_harvest:
            rule_risk = max(rule_risk, 96.0)
            flags.append("CRITICAL CREDENTIAL HARVESTING: Message solicits confidential banking authentication secrets (Card Number / ATM PIN / OTP / CVV / Password)")
            detected_scam_type = "Financial Credential Harvesting (Card Details / PIN / OTP / CVV)"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 50)
            manipulation_meter["authority"] = max(manipulation_meter["authority"], 60)

        # --- VECTOR H: Sextortion, Cyber Blackmail & Coercive Extortion ---
        # Online harassment, direct blackmail threats, illicit media solicitation (IPC 384 / IT Act Sec 66E / 67 / 67A).
        blackmail_extort_patterns = [
            r'\b(?:i\s+will\s+|will\s+|gonna\s+|to\s+)?(?:blackmail|extort)\s+(?:you|ur)\b',
            r'\b(?:blackmail(?:ing|ed)?|extort(?:ion|ing|ed)?)\b',
            r'\b(?:leak|expose|upload|post|publish)\s+(?:your\s+)?(?:nude|nudes|private|intimate|explicit|personal|recorded)\s+(?:photos?|pics?|pictures?|videos?|clip)\b',
            r'\b(?:viral\s+kar\s+dunga|leak\s+kar\s+dunga|photos?\s+viral|video\s+viral)\b',
            r'\b(?:sextortion|cyber\s*blackmail|recorded\s+your\s+video\s*call|webcam\s+recording)\b',
            r'\b(?:pay|send\s+money|transfer)\s+.*?\b(?:or\s+(?:i\s+will\s+)?(?:leak|send|post|share|expose|ruin|destroy))\b',
            r'\b(?:i\s+will\s+|will\s+|or\s+else\s+)(?:leak|expose|share|post|upload)\s+(?:them|your\s+photos?|your\s+videos?|your\s+nudes?)\b',
            r'\b(?:i\s+will\s+|will\s+|or\s+else\s+)(?:ruin|destroy|expose)\s+(?:you|ur|your\s+life|your\s+reputation)\b',
            r'\b(?:blackmail\s+karunga|barbaad\s+kar\s+dunga|dhamki\s+de\s+raha)\b'
        ]
        solicitation_patterns = [
            r'\b(?:send|share|give|show|drop|want)\s+(?:me\s+)?(?:your\s+|ur\s+)?(?:nude|nudes|naked|explicit|intimate)\s*(?:photos?|pics?|pictures?|images?|videos?|media)?\b',
            r'\b(?:can\s+(?:you|u)|please|plz)?\s*(?:send|share|give|show)\s+(?:me\s+)?(?:your\s+|ur\s+)?(?:nudes?|naked\s+pics?|intimate\s+pics?|nude\s+pictures?|nude\s+photos?)\b',
            r'\b(?:nude\s+pics?|nude\s+photos?|nude\s+pictures?|send\s+nudes?|share\s+nudes?)\b',
            r'\b(?:nude\s+(?:photo|pic|video)\s+bhejo)\b'
        ]
        safe_blackmail_advisory = re.compile(
            r'\b(?:never\s+pay|do\s+not\s+(?:pay|give\s+in|givein)|don\'t\s+(?:pay|give\s+in|givein)|report|complaint|victim\s+of|helpline|never\s+share)\b',
            re.IGNORECASE
        )
        is_safe_blackmail = bool(safe_blackmail_advisory.search(text_lower))
        
        is_blackmail_threat = not is_safe_blackmail and (
            any(re.search(p, text_lower) for p in blackmail_extort_patterns) or
            any(re.search(p, text_lower) for p in solicitation_patterns)
        )
        if is_blackmail_threat:
            rule_risk = max(rule_risk, 98.0)
            flags.append("CRITICAL CYBER BLACKMAIL / EXTORTION: Coercive threat to blackmail, extort, or expose victim detected")
            detected_scam_type = "Cyber Blackmail & Coercive Extortion"
            manipulation_meter["fear"] = max(manipulation_meter["fear"], 95)
            manipulation_meter["urgency"] = max(manipulation_meter["urgency"], 75)

        # --- URGENCY BOOST ---
        urgency_pressure_patterns = [
            r"\b(?:immediately|urgent|act now|call now|before (?:tonight|\d+)|within \d+ (?:min|hour|hr)|last chance)\b",
            r"\b(?:turant|jaldi|aaj hi|abhi call karein|aaj raat \d+ baje)\b"
        ]
        if any(re.search(p, text_lower) for p in urgency_pressure_patterns):
            manipulation_meter["urgency"] = max(manipulation_meter["urgency"], 70)
            if rule_risk > 0:
                rule_risk = min(100.0, rule_risk + 10.0)
                flags.append("HIGH-PRESSURE URGENCY: Imposes tight countdown or immediate deadline to prevent critical thinking")

        # 4. HARD NEGATIVE SAFEGUARD: Legitimate 2FA OTP & Banking Debit/Credit Receipts
        otp_receipt_pattern = r"\b(?:your\s+)?(?:otp|one time password|secret code)\s+(?:is\s+|for\s+[\w\s]+\s+is\s+)?\b\d{4,8}\b"
        safe_otp_advisory = r"\b(?:do not share|never share|not to be shared|keep secret|valid for \d+ (?:min|minute|seconds?)|bank never asks)\b"
        is_safe_otp = bool(re.search(otp_receipt_pattern, text_lower) and re.search(safe_otp_advisory, text_lower))
        
        txn_receipt_pattern = r"\b(?:a/c|account)\s*(?:no\.?\s*)?[xX*]+\d{2,6}\s+(?:is\s+)?(?:debited|credited)\s+(?:by|for|with)\s*(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d+)?\b"
        avail_bal_pattern = r"\b(?:avail(?:able)?\s+bal(?:ance)?|total bal(?:ance)?)\s*[:\-]?\s*(?:rs\.?|inr|₹)\s*[\d,]+\b"
        is_safe_receipt = bool(re.search(txn_receipt_pattern, text_lower) or re.search(avail_bal_pattern, text_lower))

        if (is_safe_otp or is_safe_receipt) and rule_risk == 0.0:
            ml_prob = min(ml_prob, 10.0)
            flags = ["VERIFIED SAFE TRANSACTION: Authentic banking debit/credit receipt or 2FA OTP alert with safety disclaimer."]
            detected_scam_type = "Legitimate Transaction Alert / Secure OTP"
            manipulation_meter = {"urgency": 0, "fear": 0, "reward": 0, "authority": 0}

        # 4B. HARD NEGATIVE SAFEGUARD: Official Cyber Awareness & 1930 Helpline Advisory
        # Public awareness posters and police bulletins use terms like "fraud", "police", "bank", "account",
        # "freeze", "immediately" to educate citizens on reporting scams to 1930 and freezing stolen funds.
        helpline_pattern = r"\b(?:1930|cybercrime\.gov\.in|#dial1930|dial\s*1930|call\s*1930|national cyber crime helpline|diang30)\b"
        advisory_phrases = [
            r"\b(?:before calling 1930|calling 1930|call 1930)\b",
            r"\b(?:to report cyber (?:fraud|crime)|report cyber (?:fraud|crime)|reporting cyber (?:fraud|crime))\b",
            r"\b(?:freeze fraudulent funds|freeze (?:fraudulent|fraud|stolen) funds)\b",
            r"\b(?:keep these details ready|keep details ready|details of the fraud|details ready)\b",
            r"\b(?:police station & district|police station and district|police station)\b",
            r"\b(?:cyber awareness|cyber advisory|public advisory|cyber safety tip|cyber dost)\b",
            r"\b(?:national cyber crime reporting portal|cybercrime reporting portal|national cyber crime)\b"
        ]
        has_helpline = bool(re.search(helpline_pattern, text_lower))
        has_advisory_phrase = any(re.search(p, text_lower) for p in advisory_phrases)
        is_official_advisory = (has_helpline and has_advisory_phrase) or (
            has_helpline and bool(re.search(r"\b(?:police|helpline|fraud|cyber)\b", text_lower)) and bool(re.search(r"\b(?:report|freeze|complaint|details|ready|station)\b", text_lower))
        )

        if is_official_advisory and rule_risk == 0.0:
            ml_prob = min(ml_prob, 4.0)
            flags = ["VERIFIED PUBLIC ADVISORY: Authentic Cyber Crime Awareness / 1930 National Helpline guideline for citizens."]
            detected_scam_type = "Official Cyber Awareness & 1930 Helpline Advisory"
            manipulation_meter = {"urgency": 0, "fear": 0, "reward": 0, "authority": 0}

        # 4C. HARD NEGATIVE SAFEGUARD: Credential Safety Warnings & Negative Advisories
        has_cred_mention = bool(re.search(r'\b(?:atm|pin|cvv|otp|password|mpin|card|credit\s*card|debit\s*card|card\s*number)\b', text_lower))
        is_safe_cred_advisory = is_negated_advice and has_cred_mention
        if is_safe_cred_advisory and rule_risk == 0.0:
            ml_prob = min(ml_prob, 8.0)
            flags = ["VERIFIED ADVISORY: Message cautions against disclosing confidential banking credentials (Card Details / ATM PIN / OTP / Password)."]
            detected_scam_type = "Legitimate Banking Advisory / Credential Safety Warning"
            manipulation_meter = {"urgency": 0, "fear": 0, "reward": 0, "authority": 0}

        # 5. Normal / Legitimate Conversation Safeguard
        # If there are NO threat vectors, no fear, no urgency, ensure generic everyday messages don't produce false positives
        is_clean_chat = (
            rule_risk == 0.0 and
            not is_safe_otp and
            not is_safe_receipt and
            not is_official_advisory and
            not is_safe_cred_advisory and
            manipulation_meter["fear"] == 0 and
            manipulation_meter["urgency"] == 0 and
            manipulation_meter["reward"] == 0
        )
        if is_clean_chat and ml_prob > 25.0:
            ml_prob = min(ml_prob, 18.0)

        # 5. Hybrid Fusion
        if rule_risk > 0:
            final_text_score = min(100.0, max(ml_prob, rule_risk))
        else:
            final_text_score = ml_prob

        final_text_score = round(final_text_score, 1)

        if not detected_scam_type:
            detected_scam_type = self._classify_scam_type(text, "")

        return {
            "risk_score": final_text_score,
            "flags": flags,
            "manipulation_meter": manipulation_meter,
            "scam_type": detected_scam_type
        }

    def analyze(self, text: str = "", url: str = "", inspect_page: bool = True, include_explanation: bool = True) -> Dict[str, Any]:
        """
        Executes end-to-end multi-modal risk scoring.
        Returns risk score (0-100), risk level, verdict, scam type,
        live sandbox inspection results, manipulation meter breakdown,
        threat security flags, and official Indian cyber helpline advice.
        """
        text = text.strip() if text else ""
        url = url.strip() if url else ""

        text_score = 0.0
        text_flags = []
        url_score = 0.0
        url_flags = []
        sandbox_inspection = None
        has_text = len(text) > 0
        has_url = len(url) > 0

        # 1. Text Threat Evaluation
        if has_text:
            text_res = self.evaluate_text(text)
            text_score = text_res["risk_score"]
            text_flags = text_res["flags"]
            manipulation_meter = text_res["manipulation_meter"]
            text_scam_type = text_res["scam_type"]
        else:
            manipulation_meter = {"urgency": 0, "fear": 0, "reward": 0, "authority": 0}
            text_scam_type = "Legitimate / None"

        # 2. URL Threat Evaluation
        valid_url_detected = False
        if has_url:
            url_result = self.evaluate_url(url)
            url_flags = list(url_result["flags"])
            if url_result.get("is_valid", False):
                url_score = url_result["risk_score"]
                valid_url_detected = True

                # Active Sandbox Inspection for non-official URLs
                if inspect_page:
                    if url_result.get("is_official", False):
                        sandbox_inspection = {
                            "status": "OFFICIAL_VERIFIED",
                            "title": "Official Portal",
                            "note": "Domain is in verified authoritative whitelist. Live sandbox crawl bypassed for speed."
                        }
                    else:
                        page_info = safe_inspect_page(url, timeout=3.5)
                        sandbox_inspection = {
                            "status": page_info["status"],
                            "http_code": page_info["http_code"],
                            "title": page_info["title"],
                            "has_password_field": page_info["has_password_field"],
                            "harvesting_fields": page_info["harvesting_fields"],
                            "brand_mismatch": page_info["brand_mismatch_detected"],
                            "live_signals": page_info["live_signals"]
                        }
                        if page_info["live_signals"]:
                            url_flags.extend(page_info["live_signals"])
                        if page_info["risk_boost"] > 0:
                            url_score = min(100.0, max(url_score, 70.0 + page_info["risk_boost"]))

                        # If page text was fetched, run text evaluation on page body
                        if page_info["extracted_text"]:
                            p_res = self.evaluate_text(page_info["extracted_text"])
                            p_prob = p_res["risk_score"]
                            sandbox_inspection["page_nlp_risk"] = round(p_prob, 1)
                            has_structural_risk = page_info["has_password_field"] or bool(page_info["harvesting_fields"]) or bool(page_info["brand_mismatch_detected"]) or (url_score > 35)
                            if p_prob > 70.0 and has_structural_risk:
                                url_flags.append(f"Live webpage content matches scam vocabulary ({p_prob:.1f}% text threat)")
                                url_score = min(100.0, max(url_score, p_prob))
            else:
                url_score = 0.0

        # 3. Composite Risk Score Fusion
        if has_text and valid_url_detected:
            # If either channel detects a high-confidence threat (>65), prioritize it
            if text_score > 65.0 or url_score > 65.0:
                final_score = min(100.0, max(text_score, url_score) * 1.05)
            else:
                final_score = (0.55 * text_score) + (0.45 * url_score)
        elif has_text:
            final_score = text_score
        elif valid_url_detected:
            final_score = url_score
        else:
            final_score = 0.0

        final_score = round(final_score, 1)

        # 4. Determine Verdict & Risk Tier
        if final_score >= 70.0:
            risk_tier = "HIGH"
            verdict = "BLOCK"
        elif final_score >= 35.0:
            risk_tier = "MEDIUM"
            verdict = "HOLD"
        else:
            risk_tier = "LOW"
            verdict = "ALLOW"

        # 5. Scam Classification
        if risk_tier in ["MEDIUM", "HIGH"]:
            if has_text and text_scam_type not in ["Generic Suspicious / Unclassified", "Legitimate / None"]:
                scam_type = text_scam_type
            else:
                scam_type = self._classify_scam_type(text, url)
        else:
            if text_scam_type in [
                "Official Cyber Awareness & 1930 Helpline Advisory",
                "Legitimate Transaction Alert / Secure OTP",
                "Legitimate Banking Advisory / Credential Safety Warning"
            ]:
                scam_type = text_scam_type
            else:
                scam_type = "Legitimate / None"

        # 7. Safe Action Guidance
        if scam_type in ["Cyber Sextortion & Intimate Media Solicitation", "Cyber Blackmail & Coercive Extortion"]:
            advice = (
                "CRITICAL CYBER THREAT: Sextortion or extortion threat detected. "
                "Never share private photos or pay blackmailers (paying never stops extortion). "
                "Immediately preserve chat screenshots as evidence, block the perpetrator, and file a complaint at "
                "https://cybercrime.gov.in or dial 1930."
            )
        elif scam_type in ["Financial Credential Harvesting (Card Details / PIN / OTP / CVV)", "Financial Credential Harvesting (ATM PIN / OTP / CVV)"]:
            advice = (
                "CRITICAL FRAUD ALERT: NEVER disclose your Credit/Debit Card numbers, ATM PIN, UPI PIN, OTP, or CVV. "
                "Banks and official institutions NEVER ask for confidential card details, PINs, or passwords. "
                "Anyone asking for your card details or ATM PIN is attempting to drain your bank account. Report immediately to 1930."
            )
        elif scam_type == "Legitimate Banking Advisory / Credential Safety Warning":
            advice = (
                "SAFE BANKING ADVISORY: This message correctly cautions users NEVER to share confidential "
                "banking credentials like ATM PIN, OTP, or CVV."
            )
        elif scam_type == "Official Cyber Awareness & 1930 Helpline Advisory":
            advice = (
                "OFFICIAL CYBER ADVISORY VERIFIED: Authentic awareness guideline from Police / National Cyber Crime "
                "Helpline (1930) instructing citizens how to report fraud and freeze funds."
            )
        elif risk_tier == "HIGH":
            advice = (
                "CRITICAL THREAT: Do not click links, send money, or provide OTP/credentials. "
                "Immediately report to National Cyber Crime Helpline: dial 1930 or lodge a complaint at "
                "https://cybercrime.gov.in."
            )
        elif risk_tier == "MEDIUM":
            advice = (
                "SUSPICIOUS ACTIVITY: Exercise extreme caution. Verify sender through official bank/organization "
                "channels before taking any action. Never share OTP or PIN numbers."
            )
        else:
            advice = (
                "CONTENT APPEARS SAFE: Normal legitimate indicators detected. Remember never to share banking "
                "passwords or OTPs with anyone."
            )

        # 8. Explainable AI (SHAP & Token Attribution)
        explanation = None
        if include_explanation:
            if self.explainer is not None:
                try:
                    explanation = self.explainer.generate_explanation(
                        text=text if has_text else "",
                        url=url if valid_url_detected else "",
                        risk_score=final_score
                    )
                except Exception as e:
                    explanation = {"error": str(e), "executive_summary": []}
            else:
                explanation = {"executive_summary": [f"Risk verdict {verdict} determined by multi-vector rule analysis."]}

        return {
            "risk_score": final_score,
            "risk_tier": risk_tier,
            "verdict": verdict,
            "scam_type": scam_type,
            "signals": {
                "text_risk_score": round(text_score, 1) if has_text else None,
                "url_risk_score": round(url_score, 1) if valid_url_detected else None
            },
            "sandbox_inspection": sandbox_inspection,
            "url_flags": text_flags + url_flags,
            "manipulation_meter": manipulation_meter,
            "safe_action_advice": advice,
            "explainability": explanation
        }

if __name__ == "__main__":
    engine = FraudShieldRiskEngine()
    print("=" * 65)
    print("[SUCCESS] RISK ENGINE WITH LIVE SANDBOX ACTIVE INSPECTOR")
    print("=" * 65)

    test_cases = [
        ("google.com", "Legitimate clean domain"),
        ("https://en.wikipedia.org/wiki/Computer_security", "Live legitimate article"),
        ("http://sbi-kyc-update.xyz/login.php", "Phishing SBI impersonation"),
        ("random words and text", "Invalid URL string")
    ]

    for inp, desc in test_cases:
        res = engine.analyze(url=inp)
        print(f"\n[{res['verdict']:5s}] ({res['risk_score']:5.1f}%) {desc:25s} -> '{inp}'")
        if res['sandbox_inspection']:
            print(f"       Sandbox Status: {res['sandbox_inspection']['status']} | Title: {res['sandbox_inspection'].get('title')}")
        if res['url_flags']:
            print(f"       Flags: {res['url_flags']}")
    print("=" * 65)
