import re
import io
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional
from PIL import Image
import numpy as np
import cv2
from logo_analyzer import LogoDomainMismatchEngine

try:
    import winocr
    HAS_WINOCR = True
except ImportError:
    HAS_WINOCR = False

try:
    import pytesseract
    HAS_PYTESSERACT = True
except ImportError:
    HAS_PYTESSERACT = False

class UniversalImageAnalyzer:
    """
    Step 7 (Universal): Comprehensive AI Image & Screenshot Threat Analyzer.
    Can inspect ANY image format:
    - WhatsApp / Telegram / SMS screenshots
    - Fake bank / KYC verification notices
    - Fake payment confirmations & UPI QR codes
    - Police / CBI / Digital Arrest warrants
    - Job offers, lottery flyers, scratch cards
    - Clean everyday documents, photos, or tickets
    """
    def __init__(self):
        # Regex patterns
        self.url_pattern = re.compile(
            r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|site|in|co|gov|edu|biz|info|live|online|club|apk)[^\s<>"]*)',
            re.IGNORECASE
        )
        self.phone_pattern = re.compile(
            r'(?:\+?91[\-\s]?)?[6-9](?:[\s\-]?\d){9}',
            re.IGNORECASE
        )
        self.upi_pattern = re.compile(
            r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
            re.IGNORECASE
        )
        self.amount_pattern = re.compile(
            r'(?:(?:Rs\.?|INR|₹|\$)\s*[\d,]+(?:\.\d+)?|\b\d+\s*(?:crore|lakh|lakhs|k)\b)',
            re.IGNORECASE
        )

        # Brand / Entity Lexicon
        self.brand_keywords = {
            "State Bank of India (SBI)": [r"\bsbi\b", r"state bank", r"onlinesbi"],
            "HDFC Bank": [r"\bhdfc\b", r"hdfcbank"],
            "ICICI Bank": [r"\bicici\b"],
            "Reserve Bank of India (RBI)": [r"\brbi\b", r"reserve bank"],
            "Paytm": [r"\bpaytm\b"],
            "PhonePe": [r"\bphonepe\b"],
            "Google Pay": [r"google pay", r"\bgpay\b"],
            "Electricity Department": [r"electricity (?:board|department|bill|power)", r"\bbescom\b", r"\btneb\b", r"\bmseb\b", r"\bdhvbn\b"],
            "Cyber Police / CBI": [r"cyber crime", r"\bcbi\b", r"police warrant", r"digital arrest", r"customs department"],
            "KBC Lucky Draw": [r"\bkbc\b", r"kaun banega", r"lucky draw"]
        }

        # Initialize OpenCV QR detector and Logo vs Domain Mismatch Engine
        self.qr_detector = cv2.QRCodeDetector()
        self.logo_mismatch_engine = LogoDomainMismatchEngine()

    def preprocess_image_for_ocr(self, pil_image: Image.Image) -> Image.Image:
        """
        Enhances image contrast and removes background noise for higher OCR readability.
        Applies Grayscale conversion, CLAHE (Contrast Limited Adaptive Histogram Equalization),
        and intelligent upscaling for small text/numbers.
        """
        try:
            rgb_arr = np.array(pil_image.convert('RGB'))
            gray = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2GRAY)
            
            # Upscale low-resolution crops or small screenshots
            h, w = gray.shape[:2]
            if w < 1000 or h < 1000:
                scale = min(2.0, 1600.0 / max(w, h))
                if scale > 1.15:
                    gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            
            # Apply CLAHE to boost contrast of text on colored gradients/flyers
            clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            
            # Convert back to PIL Image (RGB format)
            return Image.fromarray(cv2.cvtColor(enhanced, cv2.COLOR_GRAY2RGB))
        except Exception:
            return pil_image

    def detect_qr_codes(self, pil_image: Image.Image) -> Dict[str, Any]:
        """Detect and decode QR codes embedded in the image with multi-pass fallback."""
        try:
            cv_img = cv2.cvtColor(np.array(pil_image.convert('RGB')), cv2.COLOR_RGB2BGR)
            # Pass 1: Standard BGR
            data, bbox, _ = self.qr_detector.detectAndDecode(cv_img)
            if data and data.strip():
                return {
                    "has_qr": True,
                    "payload": data.strip(),
                    "type": "UPI_PAYMENT" if "upi://" in data.lower() else ("URL" if "http" in data.lower() else "TEXT")
                }
            
            # Pass 2: Grayscale
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            data, bbox, _ = self.qr_detector.detectAndDecode(gray)
            if data and data.strip():
                return {
                    "has_qr": True,
                    "payload": data.strip(),
                    "type": "UPI_PAYMENT" if "upi://" in data.lower() else ("URL" if "http" in data.lower() else "TEXT")
                }

            # Pass 3: Otsu Thresholding for faint or shadowed QR codes
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            data, bbox, _ = self.qr_detector.detectAndDecode(thresh)
            if data and data.strip():
                return {
                    "has_qr": True,
                    "payload": data.strip(),
                    "type": "UPI_PAYMENT" if "upi://" in data.lower() else ("URL" if "http" in data.lower() else "TEXT")
                }
        except Exception:
            pass
        return {"has_qr": False, "payload": "", "type": "NONE"}

    async def _async_ocr(self, img: Image.Image) -> Dict[str, Any]:
        """Calls Windows native OCR if on Windows, or pytesseract if in Linux/Cloud container."""
        if HAS_WINOCR:
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            try:
                res = await winocr.recognize_pil(img, 'en')
                lines = [line.text.strip() for line in res.lines if line.text.strip()]
                return {"text": "\n".join(lines), "lines": lines}
            except Exception as e:
                return {"text": "", "lines": [], "error": str(e)}

        if HAS_PYTESSERACT:
            try:
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, pytesseract.image_to_string, img)
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                return {"text": "\n".join(lines), "lines": lines}
            except Exception as e:
                return {"text": "", "lines": [], "error": str(e)}

        return {"text": "", "lines": []}

    def classify_image_type(self, text: str, has_qr: bool, qr_type: str) -> str:
        """Categorize what kind of image was uploaded."""
        t = text.lower()
        if has_qr and qr_type == "UPI_PAYMENT":
            return "UPI Payment QR Code"
        if re.search(r"\b(?:1930|cybercrime\.gov\.in|#dial1930|diang30)\b", t) and any(k in t for k in ["report", "helpline", "freeze", "details ready", "advisory", "awareness", "station", "fraud"]):
            return "Official Cyber Awareness & 1930 Helpline Advisory"
        if any(k in t for k in ["digital arrest", "cbi", "warrant", "customs", "interrogation"]):
            return "Digital Arrest / Legal Coercion Notice"
        if any(k in t for k in ["electricity", "power cut", "bill overdue", "disconnected tonight"]):
            return "Electricity / Utility Disconnection Notice"
        if any(k in t for k in ["pan card", "kyc", "aadhaar", "account frozen", "account suspended"]):
            return "Banking Phishing / KYC Trap"
        if any(k in t for k in ["lucky draw", "lottery", "kbc", "won", "jackpot"]):
            return "Lottery / Prize Fraud Poster"
        if any(k in t for k in ["paid to", "payment successful", "transaction successful", "debited from"]):
            return "Payment Screenshot / Transfer Confirmation"
        if any(k in t for k in ["telegram", "whatsapp", "typing...", "online", "yesterday", "am", "pm"]):
            return "Chat Screenshot / Messenger Broadcast"
        if len(text.strip()) > 30:
            return "Text Document / Flyer / Notice"
        return "General Photo / Graphic (Low Text)"

    async def analyze_image_async(self, engine, image_bytes: bytes) -> Dict[str, Any]:
        """
        Universal asynchronous image inspection pipeline.
        Pipes extracted optical text, QR payloads, and entity signals into Risk Engine.
        """
        try:
            img = Image.open(io.BytesIO(image_bytes))
            width, height = img.size
            img_format = img.format or "UNKNOWN"
        except Exception as e:
            return {
                "success": False,
                "error": f"Invalid image file: {str(e)}"
            }

        # 1. QR Code Scan
        qr_info = self.detect_qr_codes(img)

        # 2. Optical Character Recognition (with Adaptive CLAHE Multi-Pass)
        ocr_res = await self._async_ocr(img)
        raw_text = ocr_res.get("text", "")
        lines = ocr_res.get("lines", [])

        # If text is sparse or faint, test CLAHE preprocessed pass to recover low-contrast text
        if len(raw_text.strip()) < 50:
            prep_img = self.preprocess_image_for_ocr(img)
            prep_res = await self._async_ocr(prep_img)
            prep_text = prep_res.get("text", "")
            if len(prep_text.strip()) > len(raw_text.strip()):
                raw_text = prep_text
                lines = prep_res.get("lines", [])

        # 3. Extract Threat Entities (with OCR whitespace artifact healing)
        normalized_for_entities = re.sub(r'(?<=[a-zA-Z0-9\-])\s*\.\s*(?=[a-zA-Z0-9]{2,})', '.', raw_text)
        normalized_for_entities = re.sub(r'https?\s*:\s*/\s*/\s*', 'http://', normalized_for_entities)

        found_urls = []
        for match in self.url_pattern.findall(normalized_for_entities):
            clean_u = match.strip(".,;:()[]{}'\"")
            if "." in clean_u and len(clean_u) > 4:
                found_urls.append(clean_u)

        if qr_info["has_qr"] and qr_info["type"] == "URL":
            found_urls.insert(0, qr_info["payload"])

        unique_urls = list(dict.fromkeys(found_urls))

        found_phones = []
        for raw_ph in self.phone_pattern.findall(normalized_for_entities):
            clean_digits = re.sub(r'[\s\-]', '', raw_ph)
            if clean_digits not in found_phones:
                found_phones.append(clean_digits)

        found_upis = list(dict.fromkeys(self.upi_pattern.findall(raw_text)))
        found_amounts = list(dict.fromkeys(self.amount_pattern.findall(raw_text)))

        # Extract UPI ID and Amount from QR payload if present
        if qr_info["has_qr"] and qr_info["type"] == "UPI_PAYMENT":
            upi_match = re.search(r'[?&]pa=([^&]+)', qr_info["payload"], re.IGNORECASE)
            if upi_match:
                clean_pa = upi_match.group(1).strip()
                if clean_pa and clean_pa not in found_upis:
                    found_upis.insert(0, clean_pa)
            am_match = re.search(r'[?&]am=([^&]+)', qr_info["payload"], re.IGNORECASE)
            if am_match:
                clean_am = f"Rs. {am_match.group(1).strip()}"
                if clean_am not in found_amounts:
                    found_amounts.insert(0, clean_am)

        # 4. Impersonated Brands & Visual Logo Detection
        impersonated = []
        for brand, patterns in self.brand_keywords.items():
            if any(re.search(p, raw_text, re.IGNORECASE) for p in patterns):
                impersonated.append(brand)

        # Computer Vision Brand Logo & Cross-Modal Integrity Audit
        cv_img = cv2.cvtColor(np.array(img.convert('RGB')), cv2.COLOR_RGB2BGR)
        brand_audit = self.logo_mismatch_engine.audit_image_brand_integrity(
            cv_img=cv_img,
            extracted_urls=unique_urls,
            extracted_upis=found_upis,
            extracted_phones=found_phones,
            ocr_text=raw_text
        )

        for logo in brand_audit.get("detected_logos", []):
            if logo["brand"] not in impersonated:
                impersonated.append(logo["brand"])

        # 5. Image Classification
        image_category = self.classify_image_type(raw_text, qr_info["has_qr"], qr_info["type"])

        # 6. Combined Threat Analysis
        primary_url = unique_urls[0] if unique_urls else ""
        analysis_text = raw_text
        if qr_info["has_qr"]:
            analysis_text += f"\n[Embedded QR Code Payload: {qr_info['payload']}]"

        has_content = len(raw_text.strip()) > 0 or qr_info["has_qr"]

        if not has_content:
            # Completely clean photo with zero text or threats
            risk_result = {
                "risk_score": 0.0,
                "risk_tier": "LOW",
                "verdict": "ALLOW",
                "scam_type": "None / Non-Text Image",
                "signals": {"text_risk_score": 0.0, "url_risk_score": 0.0},
                "sandbox_inspection": None,
                "url_flags": [],
                "manipulation_meter": {"urgency": 0, "fear": 0, "reward": 0, "authority": 0},
                "safe_action_advice": "IMAGE APPEARS CLEAN: No deceptive text, phishing links, or fraudulent QR codes detected.",
                "explainability": {
                    "executive_summary": ["No textual or optical threat vectors found in image."],
                    "url_explainability": None,
                    "text_explainability": None
                }
            }
        else:
            # Run through FraudShield Risk Engine
            risk_result = engine.analyze(
                text=analysis_text,
                url=primary_url,
                inspect_page=True,
                include_explanation=True
            )

            # Apply Visual Brand & Logo Mismatch Override
            if brand_audit.get("mismatch_detected", False):
                penalty = brand_audit.get("risk_adjustment", 95.0)
                risk_result["risk_score"] = round(max(risk_result["risk_score"], penalty), 1)
                risk_result["risk_tier"] = "HIGH"
                risk_result["verdict"] = "BLOCK"
                m_type = brand_audit.get("mismatch_type", "LOGO_MISMATCH")
                risk_result["scam_type"] = f"Visual Brand Impersonation / {m_type.replace('_', ' ').title()}"
                
                # Prepend mismatch flags
                if "url_flags" not in risk_result:
                    risk_result["url_flags"] = []
                for f in reversed(brand_audit.get("flags", [])):
                    if f not in risk_result["url_flags"]:
                        risk_result["url_flags"].insert(0, f)
                risk_result["flags"] = list(risk_result["url_flags"])
                
                # Add to SHAP/XAI executive summary
                exec_sum = risk_result.get("explainability", {}).get("executive_summary", [])
                detected_logo_name = brand_audit.get('detected_logos', [{}])[0].get('brand', 'Official Brand')
                exec_sum.insert(0, f"CRITICAL LOGO MISMATCH: Official {detected_logo_name} visual logo detected with unauthorized digital endpoints.")

            if image_category == "Official Cyber Awareness & 1930 Helpline Advisory" and not brand_audit.get("mismatch_detected", False):
                exec_sum = risk_result.get("explainability", {}).get("executive_summary", [])
                exec_sum.clear()
                exec_sum.append("Official Cyber Awareness & 1930 Helpline advisory verified. Legitimate law enforcement educational guidance for reporting cyber fraud and freezing stolen funds.")

        return {
            "success": True,
            "image_metadata": {
                "width": width,
                "height": height,
                "format": img_format,
                "lines_count": len(lines),
                "image_category": image_category
            },
            "qr_code": qr_info,
            "extracted_text": raw_text,
            "detected_entities": {
                "urls": unique_urls,
                "phones": found_phones,
                "upi_ids": found_upis,
                "amounts": found_amounts,
                "impersonated_brands": impersonated
            },
            "brand_integrity_audit": brand_audit,
            "detected_phones": found_phones,
            "detected_urls": unique_urls,
            "primary_url": primary_url,
            "risk_analysis": risk_result
        }

    def analyze_image(self, engine, image_bytes: bytes) -> Dict[str, Any]:
        """Synchronous wrapper safe across any event loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(self.analyze_image_async(engine, image_bytes)))
                return future.result()
        else:
            return asyncio.run(self.analyze_image_async(engine, image_bytes))

    # Aliases for backwards compatibility
    scan_and_analyze_async = analyze_image_async
    scan_and_analyze = analyze_image

# Backwards compatibility alias
ScamPosterOCRScanner = UniversalImageAnalyzer

if __name__ == "__main__":
    from risk_engine import FraudShieldRiskEngine
    analyzer = UniversalImageAnalyzer()
    engine = FraudShieldRiskEngine()

    print("=" * 65)
    print("Testing Universal Image Analyzer across test images:")
    print("=" * 65)

    tests = [
        ("Electricity Scam Notice", "sample_scam_poster.png"),
        ("SBI Phishing Screenshot", "sample_sbi_screenshot.png"),
        ("UPI Lottery QR Scam", "sample_upi_qr_scam.png"),
        ("Clean Classroom Notice", "sample_clean_photo.png")
    ]

    for label, filename in tests:
        try:
            with open(filename, "rb") as f:
                res = analyzer.analyze_image(engine, f.read())
            meta = res["image_metadata"]
            ra = res["risk_analysis"]
            print(f"\n[{label}] -> {filename}")
            print(f"  Category: {meta['image_category']}")
            print(f"  Verdict:  {ra['verdict']} (Risk: {ra['risk_score']}%)")
            print(f"  Phones:   {res['detected_entities']['phones']}")
            print(f"  URLs:     {res['detected_entities']['urls']}")
            print(f"  Brands:   {res['detected_entities']['impersonated_brands']}")
        except Exception as e:
            print(f"Failed {filename}: {e}")
