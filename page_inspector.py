import re
from urllib.parse import urlparse
from typing import Dict, Any, List
import urllib3
import requests
from bs4 import BeautifulSoup

# Suppress SSL warnings during security sandbox scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KNOWN_BRANDS = {
    "sbi": ["State Bank of India", "SBI", "OnlineSBI"],
    "hdfc": ["HDFC Bank", "HDFC Netbanking"],
    "icici": ["ICICI Bank", "iMobile"],
    "paytm": ["Paytm Payments Bank", "Paytm"],
    "paypal": ["PayPal"],
    "google": ["Google Account", "Google Login", "Gmail"],
    "microsoft": ["Microsoft Account", "Office 365", "Outlook"],
    "amazon": ["Amazon Sign-In", "Amazon"],
    "netflix": ["Netflix", "Netflix Login"],
    "apple": ["Apple ID", "iCloud"],
    "electricity": ["Electricity Board", "Power Disconnection", "Electricity Bill"]
}

OFFICIAL_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.in"],
    "microsoft": ["microsoft.com", "live.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com"]
}

SENSITIVE_INPUT_KEYWORDS = [
    "otp", "cvv", "pan", "aadhaar", "pin", "card_number", "cardnumber",
    "debit", "credit", "mpin", "passcode", "secret"
]

def safe_inspect_page(url: str, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Safely crawls and inspects a webpage in a headless security sandbox.
    - Does NOT execute JavaScript (prevents client-side exploits).
    - Limits response size to prevent resource exhaustion.
    - Inspects DOM for credential harvesting forms, sensitive inputs, and deceptive titles.
    """
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str

    try:
        parsed = urlparse(url_str)
        netloc = parsed.netloc.lower().split(":")[0]
    except Exception:
        netloc = ""

    result = {
        "status": "UNREACHABLE",
        "http_code": None,
        "title": "N/A",
        "has_password_field": False,
        "harvesting_fields": [],
        "brand_mismatch_detected": None,
        "extracted_text": "",
        "live_signals": [],
        "risk_boost": 0.0
    }

    headers = {
        "User-Agent": "FraudShield-Sandbox-Bot/1.0 (+https://fraudshield.ai/scanner; security-inspection)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
    }

    try:
        # Stream response with size cutoff (max 1.5MB)
        with requests.get(url_str, headers=headers, timeout=timeout, stream=True, allow_redirects=True, verify=False) as resp:
            result["http_code"] = resp.status_code
            if resp.status_code >= 400:
                result["status"] = f"HTTP_ERROR_{resp.status_code}"
                result["live_signals"].append(f"Server returned HTTP error status {resp.status_code}")
                return result

            # Read only up to 1.5 MB
            content = b""
            for chunk in resp.iter_content(chunk_size=16384):
                content += chunk
                if len(content) > 1_500_000:
                    break
            
            html_text = content.decode("utf-8", errors="ignore")
            result["status"] = "SUCCESS"

    except requests.exceptions.Timeout:
        result["status"] = "TIMEOUT"
        result["live_signals"].append("Live inspection timed out (>3.5s). Host may be unstable, geo-blocking, or rate-limiting.")
        return result
    except requests.exceptions.RequestException as e:
        result["status"] = "OFFLINE"
        result["live_signals"].append(f"Could not connect to live host (Server down, DNS failure, or blocked).")
        return result

    # Parse DOM with BeautifulSoup
    try:
        soup = BeautifulSoup(html_text, "html.parser")

        # 1. Page Title
        if soup.title and soup.title.string:
            result["title"] = soup.title.string.strip()[:120]
        else:
            result["title"] = "No Title Specified"

        # 2. Check for Password inputs
        pw_inputs = soup.find_all("input", {"type": "password"})
        if pw_inputs:
            result["has_password_field"] = True
            result["live_signals"].append(f"Found {len(pw_inputs)} password input field(s)")
            result["risk_boost"] += 25.0

        # 3. Check for Sensitive credential harvesting fields (OTP, PAN, Aadhaar, CVV)
        found_harvest = set()
        for inp in soup.find_all(["input", "textarea"]):
            field_name = (inp.get("name") or "").lower() + " " + (inp.get("id") or "").lower() + " " + (inp.get("placeholder") or "").lower()
            for kw in SENSITIVE_INPUT_KEYWORDS:
                if re.search(r"\b" + kw + r"\b", field_name):
                    found_harvest.add(kw.upper())
        
        if found_harvest:
            result["harvesting_fields"] = list(found_harvest)
            result["live_signals"].append(f"Detected sensitive credential input field(s): {', '.join(found_harvest)}")
            result["risk_boost"] += 35.0

        # 4. Brand Mismatch Check: Title/Headers claim to be a known brand, but domain is unofficial
        combined_text = (result["title"] + " " + " ".join([h.get_text() for h in soup.find_all(["h1", "h2"])])).lower()
        for brand_key, brand_names in KNOWN_BRANDS.items():
            for name in brand_names:
                if name.lower() in combined_text:
                    # Check if domain matches official domain
                    official_hosts = OFFICIAL_DOMAINS.get(brand_key, [])
                    is_official = any(netloc == o or netloc.endswith("." + o) for o in official_hosts)
                    if not is_official and official_hosts:
                        mismatch_desc = f"Page visually claims to be '{name}', but domain '{netloc}' is NOT official {brand_key.upper()}!"
                        result["brand_mismatch_detected"] = mismatch_desc
                        result["live_signals"].append(mismatch_desc)
                        result["risk_boost"] += 50.0
                        break

        # 5. Extract Visible Page Text (for NLP model analysis)
        # Remove scripts and styling
        for element in soup(["script", "style", "noscript", "svg"]):
            element.decompose()
        clean_text = soup.get_text(separator=" ", strip=True)
        # Collapse whitespace and truncate
        clean_text = re.sub(r"\s+", " ", clean_text)[:2000]
        result["extracted_text"] = clean_text

    except Exception as ex:
        result["live_signals"].append(f"DOM parsing note: {ex}")

    return result

if __name__ == "__main__":
    print("Testing live sandbox page inspector...")
    test_urls = [
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://www.google.com"
    ]
    for u in test_urls:
        info = safe_inspect_page(u)
        print(f"\nURL: {u}")
        print(f"  Status: {info['status']} | Code: {info['http_code']}")
        print(f"  Title : {info['title']}")
        print(f"  Signals: {info['live_signals']}")
        preview = info['extracted_text'][:100].encode('ascii', errors='ignore').decode()
        print(f"  Text preview: {preview}...")
