import os
import base64
import uuid
from datetime import datetime, timezone
import uvicorn
from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from risk_engine import FraudShieldRiskEngine
from database import (
    init_db, log_incident, get_recent_incidents, get_stats,
    register_user, authenticate_user
)
from hunt_engine import run_hunt_scan
from image_analyzer import UniversalImageAnalyzer, ScamPosterOCRScanner

app = FastAPI(
    title="FraudShield AI",
    description="Multi-functional cyber defense platform hunting and preventing digital fraud",
    version="2.5.0"
)

# Initialize database, ML risk engine, and Universal Image Threat Analyzer
init_db()
engine = FraudShieldRiskEngine()
image_analyzer = UniversalImageAnalyzer()
ocr_scanner = image_analyzer

# Pydantic Schemas
class PreventRequest(BaseModel):
    text: Optional[str] = ""
    url: Optional[str] = ""

class PlatformProtectRequest(BaseModel):
    client_id: Optional[str] = "Website-X"
    content_type: Optional[str] = "auto"
    text: Optional[str] = ""
    url: Optional[str] = ""
    image_base64: Optional[str] = ""
    metadata: Optional[Dict[str, Any]] = None

class LoginRequest(BaseModel):
    identifier: str  # email or phone
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: str
    phone: str
    organization: Optional[str] = "Student Developer"
    password: str

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    svg_icon = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>
        <defs><linearGradient id='g' x1='0%' y1='0%' x2='100%' y2='100%'><stop offset='0%' stop-color='#38bdf8'/><stop offset='100%' stop-color='#0284c7'/></linearGradient></defs>
        <rect width='100' height='100' rx='24' fill='#0d121f'/>
        <path d='M50 16 L22 28 V52 C22 70 34 84 50 88 C66 84 78 70 78 52 V28 Z' fill='url(#g)'/>
        <path d='M50 30 L66 38 V52 C66 64 58 74 50 78 C42 74 34 64 34 52 V38 Z' fill='#070a13'/>
        <path d='M44 52 L48 56 L58 44' stroke='#38bdf8' stroke-width='5' stroke-linecap='round' stroke-linejoin='round' fill='none'/>
    </svg>"""
    return HTMLResponse(content=svg_icon, media_type="image/svg+xml")

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "FraudShield AI Enterprise Hub",
        "models_loaded": {
            "nlp_text_model": True,
            "url_random_forest": True,
            "live_sandbox_inspector": True,
            "hunt_engine": True
        }
    }

# ----------------- AUTHENTICATION ENDPOINTS -----------------
@app.post("/api/auth/login")
def login_endpoint(payload: LoginRequest):
    """Authenticate user via Email or Phone + Password."""
    user = authenticate_user(payload.identifier, payload.password)
    if user:
        return {"authenticated": True, "user": user}
    return JSONResponse(
        status_code=401,
        content={"error": "Invalid credentials. Please verify your Email/Phone and Password."}
    )

@app.post("/api/auth/register")
def register_endpoint(payload: RegisterRequest):
    """Register new student or team member account."""
    if not payload.name or not payload.email or not payload.phone or not payload.password:
        return JSONResponse(status_code=400, content={"error": "All fields are required."})
    
    res = register_user(
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        organization=payload.organization or "Team Hackscribe (CSE)",
        password=payload.password
    )
    if not res["success"]:
        return JSONResponse(status_code=400, content={"error": res["error"]})
    return {"registered": True, "user": res["user"]}

# ----------------- THREAT SCANNER ENDPOINTS -----------------
@app.post("/api/prevent")
def prevent_endpoint(payload: PreventRequest):
    """Pre-publish fraud prevention gate."""
    text_clean = (payload.text or "").strip()
    url_clean = (payload.url or "").strip()

    if not text_clean and not url_clean:
        return JSONResponse(
            status_code=400,
            content={"error": "Input is empty. Please enter message text or a URL to analyze."}
        )

    result = engine.analyze(text=text_clean, url=url_clean)

    # Log to SQLite
    try:
        log_incident(
            text=text_clean,
            url=url_clean,
            risk_score=result["risk_score"],
            risk_tier=result["risk_tier"],
            verdict=result["verdict"],
            scam_type=result["scam_type"]
        )
    except Exception as e:
        print("Database log warning:", e)

    return result

@app.post("/api/image-scan")
@app.post("/api/ocr-scan")
async def image_scan_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(None)
):
    """
    Step 7 (Universal): AI Image & Screenshot Threat Analyzer.
    Extracts optical text (native Windows OCR), QR code payloads (UPI/URL), 
    and threat entities (phones, UPI IDs, amounts, impersonated brands) from ANY image,
    then runs the FraudShield Risk Engine + SHAP Explainability.
    """
    image_bytes = None
    
    # 1. Check multipart file upload
    if file and file.filename:
        image_bytes = await file.read()
    else:
        # 2. Check JSON payload with image_base64
        try:
            body = await request.json()
            if "image_base64" in body:
                b64 = body["image_base64"]
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                image_bytes = base64.b64decode(b64)
        except Exception:
            pass

    if not image_bytes:
        return JSONResponse(
            status_code=400,
            content={"error": "No image data provided. Please upload an image file or provide image_base64."}
        )

    try:
        scan_res = await image_analyzer.analyze_image_async(engine, image_bytes)
        if not scan_res.get("success", False):
            return JSONResponse(status_code=400, content={"error": scan_res.get("error", "Image analysis failed")})

        # Log incident to SQLite
        try:
            ra = scan_res["risk_analysis"]
            cat = scan_res.get("image_metadata", {}).get("image_category", "Image Threat")
            preview_txt = scan_res['extracted_text'][:80] if scan_res['extracted_text'] else 'Graphic / QR Code'
            log_incident(
                text=f"[{cat}] {preview_txt}",
                url=scan_res.get("primary_url", "N/A"),
                risk_score=ra["risk_score"],
                risk_tier=ra["risk_tier"],
                verdict=ra["verdict"],
                scam_type=ra["scam_type"]
            )
        except Exception as e:
            print("Database log warning:", e)

        return scan_res
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/image-sample")
@app.get("/api/ocr-sample")
def get_image_sample(preset: str = "electricity"):
    """
    Returns sample test images as base64 for instant 1-click testing:
    - electricity: Electricity cut notice flyer
    - sbi: SBI frozen account KYC screenshot
    - upi_qr: KBC lottery UPI QR code payment flyer
    - clean: Clean campus / classroom notice
    """
    preset_files = {
        "electricity": ("sample_scam_poster.png", "Electricity Bill Cut Flyer"),
        "sbi": ("sample_sbi_screenshot.png", "SBI Frozen Account KYC Screenshot"),
        "upi_qr": ("sample_upi_qr_scam.png", "KBC Lottery UPI QR Payment Scam"),
        "clean": ("sample_clean_photo.png", "Clean Campus Symposium Notice")
    }
    
    file_info = preset_files.get(preset.lower(), preset_files["electricity"])
    filename, label = file_info
    
    try:
        with open(filename, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")
        return {
            "preset": preset,
            "label": label,
            "filename": filename,
            "image_base64": f"data:image/png;base64,{b64}"
        }
    except Exception as e:
        return JSONResponse(status_code=404, content={"error": str(e)})

@app.post("/api/v1/protect")
@app.post("/api/protect")
async def platform_protection_endpoint(payload: PlatformProtectRequest):
    """
    B2B Scam Protection Gateway for Website X.
    External websites, platforms, and gateways call this API with user-submitted text, 
    URLs, or images before publishing or delivering them.
    
    If FraudShield detects a cyber threat, it returns:
    - is_threat: true
    - action_demanded: 'BLOCK_IMMEDIATELY'
    - suggested_http_status: 403
    - enforcement_directive: Authoritative instruction to reject the submission immediately.
    """
    client_name = payload.client_id.strip() if payload.client_id else "Website-X"
    text_clean = (payload.text or "").strip()
    url_clean = (payload.url or "").strip()
    img_b64 = (payload.image_base64 or "").strip()
    scan_id = f"FS-PROT-{uuid.uuid4().hex[:8].upper()}"

    if not text_clean and not url_clean and not img_b64:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Submission payload is empty. Provide text, url, or image_base64 for Website X threat inspection."
            }
        )

    brand_audit = {"has_logo": False, "mismatch_detected": False, "flags": []}
    detected_entities = {
        "urls": [url_clean] if url_clean else [],
        "phones": [],
        "upi_ids": [],
        "amounts": []
    }
    extracted_ocr_text = ""
    qr_code_info = {"has_qr": False}

    # 1. Image inspection if provided
    if img_b64:
        try:
            raw_b64 = img_b64.split(",", 1)[1] if "," in img_b64 else img_b64
            img_bytes = base64.b64decode(raw_b64)
            img_res = await image_analyzer.analyze_image_async(engine, img_bytes)
            
            if img_res.get("success", False):
                extracted_ocr_text = img_res.get("extracted_text", "")
                brand_audit = img_res.get("brand_integrity_audit", brand_audit)
                qr_code_info = img_res.get("qr_code", qr_code_info)
                
                # Merge entities
                ent = img_res.get("detected_entities", {})
                for k in ["urls", "phones", "upi_ids", "amounts"]:
                    detected_entities[k] = list(dict.fromkeys(detected_entities.get(k, []) + ent.get(k, [])))
                
                # Combined risk analysis from image
                risk_analysis = img_res.get("risk_analysis", {})
                
                # If explicit text or url was also passed, combine analysis
                if text_clean or url_clean:
                    merged_text = f"{text_clean}\n{extracted_ocr_text}".strip()
                    primary_u = url_clean or (detected_entities["urls"][0] if detected_entities["urls"] else "")
                    text_risk = engine.analyze(text=merged_text, url=primary_u, inspect_page=True, include_explanation=True)
                    if text_risk.get("risk_score", 0) > risk_analysis.get("risk_score", 0):
                        risk_analysis = text_risk
            else:
                risk_analysis = engine.analyze(text=text_clean, url=url_clean)
        except Exception as e:
            risk_analysis = engine.analyze(text=text_clean, url=url_clean)
    else:
        # 2. Text / URL inspection
        risk_analysis = engine.analyze(text=text_clean, url=url_clean, inspect_page=True, include_explanation=True)

    risk_score = float(risk_analysis.get("risk_score", 0.0))
    verdict = risk_analysis.get("verdict", "ALLOW")
    risk_tier = risk_analysis.get("risk_tier", "LOW")
    scam_type = risk_analysis.get("scam_type", "General Content")
    mismatch_detected = brand_audit.get("mismatch_detected", False)

    # 3. Formulate Action Demanded to Website X
    reasons = []
    if mismatch_detected:
        reasons.extend(brand_audit.get("flags", []))
    if risk_analysis.get("flags"):
        for f in risk_analysis.get("flags", []):
            if f not in reasons:
                reasons.append(f)
    if risk_analysis.get("url_flags"):
        for f in risk_analysis.get("url_flags", []):
            if f not in reasons:
                reasons.append(f)

    manipulation = risk_analysis.get("manipulation_meter", {})
    if manipulation.get("fear", 0) > 60:
        reasons.append(f"Severe Fear / Coercion trigger detected ({manipulation['fear']}%)")
    if manipulation.get("urgency", 0) > 60:
        reasons.append(f"High Urgency pressure detected ({manipulation['urgency']}%)")

    # Authoritative Enforcement Directive
    if verdict == "BLOCK" or risk_score >= 70.0 or mismatch_detected:
        is_threat = True
        action_demanded = "BLOCK_IMMEDIATELY"
        suggested_http_status = 403
        action_urgency = "CRITICAL_ACTION_REQUIRED"
        enforcement_directive = (
            f"DEMAND TO {client_name.upper()}: BLOCK IMMEDIATELY. "
            f"Do NOT allow user submission to be published, saved, or delivered. "
            f"Return HTTP 403 Forbidden to the initiating client and terminate suspicious session."
        )
    elif verdict == "REVIEW" or risk_score >= 40.0:
        is_threat = True
        action_demanded = "QUARANTINE_FOR_REVIEW"
        suggested_http_status = 202
        action_urgency = "MODERATE_REVIEW_REQUIRED"
        enforcement_directive = (
            f"DEMAND TO {client_name.upper()}: QUARANTINE SUBMISSION. "
            f"Hold content in human moderation queue before displaying publicly."
        )
    else:
        is_threat = False
        action_demanded = "ALLOW_PUBLISH"
        suggested_http_status = 200
        action_urgency = "CLEAR"
        enforcement_directive = (
            f"AUTHORIZATION FOR {client_name.upper()}: CLEAR TO PUBLISH. "
            f"No scam patterns, phishing vectors, or brand impersonation detected. Safe to deliver."
        )

    # Log incident to SQLite audit trail
    try:
        log_incident(
            text=f"[API-PROTECT: {client_name}] {text_clean[:60] if text_clean else (extracted_ocr_text[:60] if extracted_ocr_text else 'Media Inspection')}",
            url=url_clean or (detected_entities['urls'][0] if detected_entities['urls'] else 'N/A'),
            risk_score=risk_score,
            risk_tier=risk_tier,
            verdict=verdict,
            scam_type=scam_type
        )
    except Exception as e:
        print("Database log warning:", e)

    return {
        "status": "PROCESSED",
        "client_id": client_name,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_threat": is_threat,
        "action_demanded": action_demanded,
        "action_urgency": action_urgency,
        "enforcement_directive": enforcement_directive,
        "suggested_http_response": {
            "status_code": suggested_http_status,
            "headers": {
                "X-FraudShield-Decision": action_demanded,
                "X-FraudShield-Risk-Score": str(risk_score),
                "X-FraudShield-Scan-ID": scan_id
            },
            "client_body": {
                "allowed": not is_threat,
                "action": action_demanded,
                "reason": reasons[0] if (is_threat and reasons) else "Content passed FraudShield security audit."
            }
        },
        "threat_analysis": {
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "verdict": verdict,
            "threat_type": scam_type,
            "reasons": reasons,
            "manipulation_meter": manipulation,
            "brand_integrity": brand_audit
        },
        "detected_entities": detected_entities,
        "qr_code": qr_code_info,
        "safe_action_advice": risk_analysis.get("safe_action_advice", "")
    }

@app.get("/api/hunt")
def hunt_endpoint(max_items: int = 8):
    """Autonomous Threat Hunter scanning live public feeds."""
    try:
        threats = run_hunt_scan(engine, max_items=max_items)
        return {"status": "SUCCESS", "threats_found": len(threats), "threats": threats}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/incidents")
def incidents_endpoint():
    """Retrieve audit trail logs and live KPI stats from SQLite."""
    stats = get_stats()
    recent = get_recent_incidents(limit=25)
    return {"stats": stats, "incidents": recent}

# ----------------- VISUALLY STUNNING FRONTEND -----------------
@app.get("/", response_class=HTMLResponse)
def multi_functional_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ FraudShield AI | Cyber Threat Defense Command</title>
        <link rel="icon" type="image/svg+xml" href="/favicon.ico">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #060913;
                --surface: #0c1220;
                --surface-card: #111a2e;
                --surface-elevated: #16223d;
                --border: #1e2d4d;
                --border-bright: #2d4373;
                --text-muted: #8b9bb4;
                --text-body: #cbd5e1;
                --text-heading: #f8fafc;
                --accent: #38bdf8;
                --accent-glow: rgba(56, 189, 248, 0.3);
                --accent-dark: #0284c7;
                --green: #10b981;
                --green-glow: rgba(16, 185, 129, 0.25);
                --yellow: #f59e0b;
                --red: #f43f5e;
                --red-glow: rgba(244, 63, 94, 0.3);
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Plus Jakarta Sans', sans-serif;
                background-color: var(--bg);
                color: var(--text-body);
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                background-image: 
                    radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
                    radial-gradient(at 100% 100%, rgba(2, 132, 199, 0.06) 0px, transparent 50%);
            }

            /* TOP NAVBAR */
            .navbar {
                background: rgba(12, 18, 32, 0.85);
                backdrop-filter: blur(12px);
                border-bottom: 1px solid var(--border);
                padding: 12px 28px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            .brand-group {
                display: flex;
                align-items: center;
                gap: 14px;
            }
            .brand-shield {
                width: 40px;
                height: 40px;
                background: linear-gradient(135deg, #0284c7, #38bdf8);
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 22px;
                box-shadow: 0 0 20px var(--accent-glow);
                animation: pulse-glow 3s infinite alternate;
            }
            @keyframes pulse-glow {
                from { box-shadow: 0 0 12px var(--accent-glow); }
                to { box-shadow: 0 0 24px rgba(56, 189, 248, 0.5); }
            }
            .brand-title {
                font-size: 19px;
                font-weight: 800;
                color: var(--text-heading);
                letter-spacing: -0.5px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .tag-pro {
                font-size: 11px;
                background: rgba(56, 189, 248, 0.15);
                color: var(--accent);
                border: 1px solid rgba(56, 189, 248, 0.35);
                padding: 2px 7px;
                border-radius: 999px;
                font-weight: 700;
            }
            .brand-sub {
                font-size: 11px;
                color: var(--text-muted);
                font-weight: 500;
            }

            /* NAVIGATION TABS */
            .nav-tabs {
                display: flex;
                gap: 6px;
                background: #080d1a;
                padding: 4px;
                border-radius: 12px;
                border: 1px solid var(--border);
            }
            .nav-tab-btn {
                background: transparent;
                border: none;
                color: var(--text-muted);
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 600;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .nav-tab-btn:hover {
                color: var(--text-heading);
                background: rgba(255, 255, 255, 0.04);
            }
            .nav-tab-btn.active {
                background: var(--surface-card);
                color: var(--accent);
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
                border: 1px solid var(--border-bright);
            }

            /* AUTH BUTTON & USER PROFILE BADGE */
            .auth-container {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .btn-auth-trigger {
                background: linear-gradient(135deg, rgba(56, 189, 248, 0.15), rgba(2, 132, 199, 0.25));
                border: 1px solid rgba(56, 189, 248, 0.4);
                color: var(--accent);
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 700;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.2s;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .btn-auth-trigger:hover {
                background: linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(2, 132, 199, 0.4));
                box-shadow: 0 0 15px var(--accent-glow);
            }
            .profile-badge {
                display: none;
                align-items: center;
                gap: 10px;
                background: var(--surface-card);
                border: 1px solid var(--border-bright);
                padding: 5px 12px 5px 6px;
                border-radius: 999px;
                cursor: pointer;
                transition: border-color 0.2s;
            }
            .profile-badge:hover {
                border-color: var(--accent);
            }
            .profile-avatar {
                width: 28px;
                height: 28px;
                border-radius: 50%;
                background: linear-gradient(135deg, #10b981, #059669);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 13px;
                font-weight: 700;
                color: white;
            }
            .profile-info {
                display: flex;
                flex-direction: column;
                text-align: left;
            }
            .profile-name {
                font-size: 12px;
                font-weight: 700;
                color: var(--text-heading);
            }
            .profile-role {
                font-size: 10px;
                color: var(--green);
                font-weight: 600;
            }

            /* MAIN LAYOUT */
            .main-shell {
                max-width: 1100px;
                width: 100%;
                margin: 28px auto;
                padding: 0 20px;
                flex: 1;
            }
            .tab-content {
                display: none;
                animation: fadeInUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            }
            .tab-content.active {
                display: block;
            }
            @keyframes fadeInUp {
                from { opacity: 0; transform: translateY(8px); }
                to { opacity: 1; transform: translateY(0); }
            }

            /* CARDS & CONTAINERS */
            .card {
                background: var(--surface-card);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 24px;
                margin-bottom: 22px;
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
                position: relative;
            }
            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 18px;
            }
            .card-title {
                font-size: 17px;
                font-weight: 700;
                color: var(--text-heading);
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .card-desc {
                font-size: 13px;
                color: var(--text-muted);
                margin-top: 4px;
            }

            /* PRESET CHIPS */
            .chips-container {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin-bottom: 20px;
            }
            .chip-btn {
                background: var(--surface);
                border: 1px solid var(--border);
                color: var(--text-body);
                padding: 7px 13px;
                border-radius: 8px;
                font-size: 12px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
            .chip-btn:hover {
                background: var(--surface-elevated);
                border-color: var(--accent);
                color: var(--text-heading);
                transform: translateY(-1px);
            }

            /* INPUT FORMS */
            .form-label {
                display: block;
                font-weight: 600;
                margin-bottom: 6px;
                font-size: 13px;
                color: #e2e8f0;
            }
            textarea, input[type="text"], input[type="password"], input[type="email"], input[type="tel"], select {
                width: 100%;
                background: #090e1a;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 8px;
                color: #ffffff;
                padding: 12px 14px;
                font-size: 14px;
                font-family: inherit;
                box-sizing: border-box;
                margin-bottom: 16px;
                transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
            }
            textarea::placeholder, input::placeholder {
                color: #64748b;
                font-size: 13.5px;
            }
            textarea:focus, input[type="text"]:focus, input[type="password"]:focus, input[type="email"]:focus, input[type="tel"]:focus, select:focus {
                outline: none;
                background: #0b1324;
                border-color: var(--accent);
                box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.18);
            }
            .password-wrapper {
                position: relative;
                width: 100%;
                margin-bottom: 16px;
            }
            .password-wrapper input {
                margin-bottom: 0 !important;
                padding-right: 44px !important;
            }
            .btn-toggle-pass {
                position: absolute;
                right: 8px;
                top: 50%;
                transform: translateY(-50%);
                background: transparent;
                border: none;
                color: #64748b;
                cursor: pointer;
                padding: 6px 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 6px;
                transition: color 0.2s, background-color 0.2s;
            }
            .btn-toggle-pass:hover {
                color: var(--accent);
                background: rgba(56, 189, 248, 0.1);
            }
            .btn-toggle-pass svg {
                width: 18px;
                height: 18px;
                stroke: currentColor;
            }

            /* BUTTONS */
            .btn-action-row {
                display: flex;
                gap: 12px;
            }
            .btn-scan-primary {
                flex: 1;
                background: linear-gradient(135deg, #0284c7, #2563eb);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 13px 22px;
                font-weight: 700;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.2s;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                box-shadow: 0 4px 15px rgba(2, 132, 199, 0.35);
            }
            .btn-scan-primary:hover:not(:disabled) {
                background: linear-gradient(135deg, #0369a1, #1d4ed8);
                box-shadow: 0 6px 20px rgba(2, 132, 199, 0.5);
                transform: translateY(-1px);
            }
            .btn-scan-primary:disabled {
                opacity: 0.65;
                cursor: not-allowed;
            }
            .btn-clear-ghost {
                background: var(--surface);
                border: 1px solid var(--border);
                color: var(--text-muted);
                padding: 13px 18px;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                font-size: 14px;
                transition: all 0.2s;
            }
            .btn-clear-ghost:hover {
                background: var(--surface-elevated);
                color: var(--text-heading);
            }

            /* ALERTS */
            .alert-box {
                display: none;
                background: rgba(244, 63, 94, 0.12);
                border: 1px solid rgba(244, 63, 94, 0.35);
                color: #fda4af;
                padding: 12px 16px;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 16px;
            }

            /* SCAN VERDICT BANNER */
            .verdict-banner {
                padding: 16px;
                border-radius: 10px;
                font-weight: 800;
                font-size: 18px;
                text-align: center;
                margin-bottom: 20px;
                letter-spacing: -0.3px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }
            .verdict-ALLOW { background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); color: #34d399; }
            .verdict-HOLD { background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4); color: #fbbf24; }
            .verdict-BLOCK { background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.45); color: #fb7185; }

            /* GRIDS */
            .grid-2 {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 14px;
                margin-bottom: 18px;
            }
            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 14px;
                margin-bottom: 20px;
            }
            .stat-box {
                background: #080d1a;
                border: 1px solid var(--border);
                border-radius: 10px;
                padding: 15px;
            }
            .stat-title { font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
            .stat-value { font-size: 22px; font-weight: 800; color: var(--text-heading); margin-top: 4px; }
            
            /* PROGRESS METER BARS */
            .meter-bar {
                background: #1e293b;
                height: 8px;
                border-radius: 4px;
                overflow: hidden;
                margin-top: 8px;
            }
            .meter-fill {
                height: 100%;
                background: var(--accent);
                width: 0%;
                transition: width 0.7s cubic-bezier(0.16, 1, 0.3, 1);
            }

            /* ADVICE & SANDBOX CARDS */
            .advice-card {
                background: #080d1a;
                border-left: 4px solid var(--accent);
                padding: 14px 16px;
                font-size: 13px;
                color: #e2e8f0;
                border-radius: 0 10px 10px 0;
                line-height: 1.5;
            }
            .sandbox-box {
                background: #080d1a;
                border: 1px solid rgba(56, 189, 248, 0.3);
                border-radius: 10px;
                padding: 15px;
                margin-top: 16px;
            }

            /* TABLES */
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
                font-size: 13px;
            }
            th {
                text-align: left;
                padding: 12px 14px;
                background: #080d1a;
                color: var(--text-muted);
                font-weight: 700;
                border-bottom: 1px solid var(--border);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            td {
                padding: 12px 14px;
                border-bottom: 1px solid var(--border);
                color: var(--text-body);
            }
            tr:hover td {
                background: rgba(255, 255, 255, 0.02);
            }
            .badge-chip {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 6px;
                font-size: 11px;
                font-weight: 700;
            }
            .badge-BLOCK { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.35); }
            .badge-HOLD { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }
            .badge-ALLOW { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }

            /* CODE BOX */
            .code-box {
                background: #050811;
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 14px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                color: #38bdf8;
                overflow-x: auto;
                position: relative;
            }

            /* SHAP ATTRIBUTION BARS */
            .shap-item {
                display: flex;
                align-items: center;
                justify-content: space-between;
                font-size: 12px;
                padding: 7px 10px;
                background: rgba(255, 255, 255, 0.02);
                border-radius: 6px;
                border: 1px solid rgba(255, 255, 255, 0.05);
            }
            .shap-name {
                font-weight: 600;
                color: #e2e8f0;
                max-width: 65%;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .shap-badge-fraud {
                font-size: 11px;
                font-weight: 700;
                color: #fb7185;
                background: rgba(244, 63, 94, 0.15);
                padding: 2px 7px;
                border-radius: 4px;
                border: 1px solid rgba(244, 63, 94, 0.3);
            }
            .shap-badge-safe {
                font-size: 11px;
                font-weight: 700;
                color: #34d399;
                background: rgba(16, 185, 129, 0.15);
                padding: 2px 7px;
                border-radius: 4px;
                border: 1px solid rgba(16, 185, 129, 0.3);
            }

            /* DROPZONE & POSTER SCANNER STYLES */
            .dropzone-box {
                border: 2px dashed rgba(56, 189, 248, 0.35);
                background: rgba(15, 23, 42, 0.5);
                border-radius: 12px;
                padding: 30px 20px;
                text-align: center;
                cursor: pointer;
                transition: all 0.25s ease;
                margin-bottom: 16px;
            }
            .dropzone-box:hover, .dropzone-box.dragover {
                border-color: #38bdf8;
                background: rgba(56, 189, 248, 0.08);
                box-shadow: 0 0 20px rgba(56, 189, 248, 0.15);
            }
            .dropzone-icon {
                font-size: 36px;
                margin-bottom: 6px;
            }
            .poster-preview-img {
                max-width: 100%;
                max-height: 260px;
                border-radius: 8px;
                border: 1px solid var(--border);
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
                object-fit: contain;
                display: block;
                margin: 0 auto;
            }

            /* MODAL SYSTEM */
            .modal-overlay {
                display: none;
                position: fixed;
                top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(4, 7, 15, 0.85);
                backdrop-filter: blur(8px);
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }
            .modal-window {
                background: var(--surface-card);
                border: 1px solid var(--border-bright);
                border-radius: 16px;
                max-width: 460px;
                width: 90%;
                padding: 28px;
                box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
                animation: modalIn 0.25s ease;
            }
            @keyframes modalIn {
                from { opacity: 0; transform: scale(0.96); }
                to { opacity: 1; transform: scale(1); }
            }
            .modal-tabs {
                display: flex;
                background: #070b14;
                border-radius: 10px;
                border: 1px solid var(--border);
                padding: 4px;
                margin-bottom: 20px;
            }
            .modal-tab-btn {
                flex: 1;
                background: transparent;
                border: none;
                color: var(--text-muted);
                padding: 9px;
                border-radius: 7px;
                font-size: 13px;
                font-weight: 700;
                cursor: pointer;
            }
            .modal-tab-btn.active {
                background: var(--surface-card);
                color: var(--accent);
                box-shadow: 0 2px 8px rgba(0,0,0,0.4);
            }
            .spinner-icon {
                display: inline-block;
                width: 14px;
                height: 14px;
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-top-color: white;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
            }
            @keyframes spin { to { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <!-- TOP NAVIGATION -->
        <header class="navbar">
            <div class="brand-group">
                <div class="brand-shield">🛡️</div>
                <div class="brand-title">
                    <span>FraudShield AI</span>
                </div>
            </div>

            <nav class="nav-tabs">
                <button class="nav-tab-btn active" onclick="switchNavTab('prevent')">⚡ Prevent Gate</button>
                <button class="nav-tab-btn" onclick="switchNavTab('ocr')">🖼️ Image Threat Analyzer</button>
                <button class="nav-tab-btn" onclick="switchNavTab('hunt')">🎯 Threat Hunter</button>
                <button class="nav-tab-btn" onclick="switchNavTab('logs')">📊 Incident Logs</button>
                <button class="nav-tab-btn" onclick="switchNavTab('api')">⚡ API Hub</button>
            </nav>

            <div class="auth-container">
                <button id="btnOpenAuth" class="btn-auth-trigger" onclick="openAuthModal()">
                    <span>👤 Sign In / Register</span>
                </button>

                <div id="userProfilePill" class="profile-badge" onclick="openProfileModal()">
                    <div class="profile-avatar" id="avatarLetter">K</div>
                    <div class="profile-info">
                        <span class="profile-name" id="badgeUserName">Karthik V.</span>
                        <span class="profile-role" id="badgeUserOrg">Team Hackscribe (CSE)</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- MAIN PLATFORM SHELL -->
        <main class="main-shell">
            <!-- TAB 1: PREVENT GATE -->
            <section id="pane-prevent" class="tab-content active">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <h2 class="card-title">⚡ Pre-Publish Threat Defense Gate</h2>
                            <p class="card-desc">Simulates how SMS gateways, telecom APIs, and social platforms evaluate content before it is delivered.</p>
                        </div>
                    </div>

                    <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:10px; letter-spacing:0.5px;">
                        ⚡ Quick Evaluation Presets (Live Testing):
                    </div>
                    <div class="chips-container">
                        <button class="chip-btn" onclick="loadTestPreset('electricity')">⚡ Electricity Bill Cut Scam</button>
                        <button class="chip-btn" onclick="loadTestPreset('sbi_kyc')">⚡ SBI PAN KYC Threat</button>
                        <button class="chip-btn" onclick="loadTestPreset('lottery')">⚡ KBC Lucky Draw Scam</button>
                        <button class="chip-btn" onclick="loadTestPreset('legit')">⚡ Safe Everyday Message</button>
                        <button class="chip-btn" onclick="loadTestPreset('phish_url')">⚡ Rogue Bank Link (.xyz)</button>
                    </div>

                    <div id="scanAlertBox" class="alert-box"></div>

                    <label class="form-label" for="txtMessage">Message / SMS / Post Body Content:</label>
                    <textarea id="txtMessage" rows="3" placeholder="Paste incoming SMS, Telegram broadcast, or user post here..."></textarea>

                    <label class="form-label" for="txtUrl">Attached Web Link / Domain (Optional):</label>
                    <input type="text" id="txtUrl" placeholder="e.g. http://sbi-kyc-update.xyz/login.php or google.com">

                    <div class="btn-action-row">
                        <button id="btnExecuteScan" class="btn-scan-primary" onclick="executeFraudScan()">
                            <span>🛡️ Scan Threat Vectors</span>
                        </button>
                        <button class="btn-clear-ghost" onclick="resetPreventForm()">Clear</button>
                    </div>
                </div>

                <!-- SCAN RESULTS CONTAINER -->
                <div id="scanResultContainer" class="card" style="display:none;">
                    <div id="verdictBanner" class="verdict-banner"></div>

                    <div class="grid-2">
                        <div class="stat-box">
                            <div class="stat-title">Composite Risk Index</div>
                            <div class="stat-value" id="resRiskScore">0 / 100</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Threat Taxonomy Classification</div>
                            <div class="stat-value" style="font-size:16px; margin-top:6px;" id="resScamType">-</div>
                        </div>
                    </div>

                    <h4 style="margin: 16px 0 10px 0; color:#f8fafc; font-size:13px; text-transform:uppercase; letter-spacing:0.5px;">
                        🧠 Psychological Manipulation Meter:
                    </h4>
                    <div class="grid-2">
                        <div class="stat-box">
                            <div class="stat-title">Urgency Pressure: <span id="valUrgency" style="color:#38bdf8;">0%</span></div>
                            <div class="meter-bar"><div id="barUrgency" class="meter-fill"></div></div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Fear / Coercion: <span id="valFear" style="color:#f43f5e;">0%</span></div>
                            <div class="meter-bar"><div id="barFear" class="meter-fill" style="background:#f43f5e;"></div></div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Reward / Greed: <span id="valReward" style="color:#f59e0b;">0%</span></div>
                            <div class="meter-bar"><div id="barReward" class="meter-fill" style="background:#f59e0b;"></div></div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Authority Impersonation: <span id="valAuthority" style="color:#a855f7;">0%</span></div>
                            <div class="meter-bar"><div id="barAuthority" class="meter-fill" style="background:#a855f7;"></div></div>
                        </div>
                    </div>

                    <div id="sandboxCard" class="sandbox-box" style="display:none;">
                        <h4 style="margin: 0 0 6px 0; color:#38bdf8; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">
                            🌐 Live AI Sandbox Crawler (Safe Headless Inspection):
                        </h4>
                        <div style="font-size:13px; color:#cbd5e1; line-height:1.5;" id="sandboxSummary"></div>
                    </div>

                    <div id="urlFlagsCard" style="display:none; margin-top:14px; background:#080d1a; padding:15px; border-radius:10px; border:1px solid var(--border);">
                        <h4 style="margin: 0 0 8px 0; color:#38bdf8; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">
                            🔍 Forensic Threat Indicators & Explanations:
                        </h4>
                        <ul id="urlFlagsList" style="margin:0; padding-left:20px; font-size:13px; color:#e2e8f0; line-height:1.6;"></ul>
                    </div>

                    <!-- STEP 6: SHAP & XAI EXPLAINABILITY CARD -->
                    <div id="shapCard" style="display:none; margin-top:16px; background:#070c18; padding:16px; border-radius:12px; border:1px solid #1e293b;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <h4 style="margin:0; color:#38bdf8; font-size:12px; text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:8px;">
                                <span>🧠 AI Decision Explainability (SHAP & Feature Attribution)</span>
                                <span style="font-size:10px; background:rgba(56,189,248,0.15); color:#38bdf8; padding:2px 8px; border-radius:999px; border:1px solid rgba(56,189,248,0.3);">Transparent XAI</span>
                            </h4>
                        </div>
                        <div id="shapExecutiveSummary" style="font-size:13px; color:#e2e8f0; line-height:1.6; margin-bottom:14px; padding:10px; background:rgba(255,255,255,0.03); border-radius:8px; border-left:3px solid #38bdf8;"></div>

                        <div class="grid-2">
                            <!-- URL SHAP Factors -->
                            <div id="shapUrlBox" style="background:#050811; border:1px solid var(--border); border-radius:8px; padding:12px;">
                                <div style="font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-bottom:8px;">
                                    🌐 URL Factors (SHAP TreeExplainer):
                                </div>
                                <div id="shapUrlList" style="display:flex; flex-direction:column; gap:6px;"></div>
                            </div>

                            <!-- NLP Text Word Impact -->
                            <div id="shapTextBox" style="background:#050811; border:1px solid var(--border); border-radius:8px; padding:12px;">
                                <div style="font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-bottom:8px;">
                                    📝 Text Linguistic Impact (Token Attributions):
                                </div>
                                <div id="shapTextList" style="display:flex; flex-direction:column; gap:6px;"></div>
                            </div>
                        </div>
                    </div>

                    <h4 style="margin: 18px 0 8px 0; color:#f8fafc; font-size:13px; text-transform:uppercase; letter-spacing:0.5px;">
                        🚨 National Citizen Defense & Helpline Escalation:
                    </h4>
                    <div class="advice-card" id="adviceSummary"></div>
                </div>
            </section>

            <!-- TAB: UNIVERSAL IMAGE THREAT ANALYZER (STEP 7) -->
            <section id="pane-ocr" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <h2 class="card-title">🖼️ Universal Image & Screenshot Threat Analyzer</h2>
                            <p class="card-desc">Inspect ANY image — WhatsApp chat screenshots, fake payment receipts, UPI QR codes, bank KYC notices, police warrants, or clean documents. Decodes embedded QR codes, extracts optical text via native OCR, and provides SHAP explainability.</p>
                        </div>
                    </div>

                    <!-- Dropzone -->
                    <div id="ocrDropzone" class="dropzone-box" onclick="document.getElementById('fileOcrInput').click()">
                        <div class="dropzone-icon">🖼️</div>
                        <div style="font-size:15px; font-weight:700; color:#fff; margin-bottom:4px;">Drag & Drop ANY Image, Screenshot, or QR Code Here</div>
                        <div style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Supports PNG, JPG, JPEG, WEBP • Screenshots, Posters, UPI QR Codes, Documents, Photos</div>
                        
                        <div style="display:flex; justify-content:center; gap:10px; margin-bottom:12px;">
                            <button type="button" class="btn-clear-ghost" style="pointer-events:none; padding:7px 16px;">Browse Image File</button>
                        </div>

                        <div style="display:flex; justify-content:center; align-items:center; flex-wrap:wrap; gap:8px;" onclick="event.stopPropagation();">
                            <span style="font-size:11px; color:#94a3b8; font-weight:600; margin-right:4px;">1-CLICK TEST SAMPLES:</span>
                            <button type="button" class="btn-clear-ghost" style="border-color:#38bdf888; color:#38bdf8; font-size:12px; padding:5px 12px;" onclick="loadPresetSample('electricity')">⚡ Electricity Notice</button>
                            <button type="button" class="btn-clear-ghost" style="border-color:#f59e0b88; color:#f59e0b; font-size:12px; padding:5px 12px;" onclick="loadPresetSample('sbi')">⚡ SBI KYC Screenshot</button>
                            <button type="button" class="btn-clear-ghost" style="border-color:#f43f5e88; color:#f43f5e; font-size:12px; padding:5px 12px;" onclick="loadPresetSample('upi_qr')">⚡ UPI QR Scam Flyer</button>
                            <button type="button" class="btn-clear-ghost" style="border-color:#10b98188; color:#10b981; font-size:12px; padding:5px 12px;" onclick="loadPresetSample('clean')">⚡ Clean Campus Notice</button>
                        </div>
                        <input type="file" id="fileOcrInput" accept="image/*" style="display:none;" onchange="handleOcrFileSelected(this.files[0])">
                    </div>

                    <div id="ocrAlertBox" class="alert-box"></div>

                    <!-- OCR IN-PROGRESS SPINNER -->
                    <div id="ocrLoading" style="display:none; text-align:center; padding:30px 0;">
                        <div class="spinner-icon" style="width:28px; height:28px; border-width:3px; border-top-color:#38bdf8;"></div>
                        <div style="margin-top:12px; color:#38bdf8; font-weight:700; font-size:14px;">Extracting Optical Text, Decoding QR Codes & Running Risk Engine...</div>
                    </div>

                    <!-- OCR RESULTS WRAPPER -->
                    <div id="ocrResultsWrapper" style="display:none; margin-top:10px;">
                        <div class="grid-2" style="margin-bottom:20px;">
                            <!-- Preview Thumbnail & QR Payload -->
                            <div style="background:#080d1a; border:1px solid var(--border); border-radius:10px; padding:14px; text-align:center;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                                    <span style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase;">📷 Image Preview:</span>
                                    <span id="ocrCategoryTag" style="font-size:11px; font-weight:700; background:rgba(56,189,248,0.15); color:#38bdf8; padding:3px 9px; border-radius:6px; border:1px solid rgba(56,189,248,0.3);">Image</span>
                                </div>
                                <img id="ocrPreviewImage" class="poster-preview-img" alt="Uploaded Image Preview">
                                <div id="ocrImageMetaText" style="font-size:11px; color:#64748b; margin-top:8px;"></div>
                                <div id="ocrQrCodeBox" style="display:none; margin-top:10px; text-align:left; background:rgba(244,63,94,0.08); border:1px solid rgba(244,63,94,0.25); border-radius:8px; padding:8px 10px;">
                                    <div style="font-size:11px; font-weight:700; color:#fb7185; margin-bottom:4px;" id="ocrQrTypeTitle">📱 Embedded QR Code:</div>
                                    <code id="ocrQrPayloadText" style="font-size:11px; color:#e2e8f0; word-break:break-all;"></code>
                                </div>
                            </div>

                            <!-- Extracted Content & Threat Entities -->
                            <div style="background:#080d1a; border:1px solid var(--border); border-radius:10px; padding:14px;">
                                <div style="font-size:11px; font-weight:700; color:#38bdf8; text-transform:uppercase; margin-bottom:10px;">
                                    📝 Extracted Threat Entities & Text:
                                </div>
                                <div id="ocrEntitiesBox" style="margin-bottom:10px; display:flex; flex-wrap:wrap; gap:6px;"></div>
                                <div class="code-box" id="ocrExtractedText" style="max-height:190px; color:#cbd5e1; font-size:12px; white-space:pre-wrap;"></div>
                            </div>
                        </div>

                        <!-- Full Risk Assessment for Image -->
                        <div class="card" style="margin-top:0;">
                            <div id="ocrVerdictBanner" class="verdict-banner"></div>

                            <!-- Computer Vision Brand & Logo Integrity Audit Box -->
                            <div id="ocrBrandAuditBox" style="display:none; margin-bottom:16px;"></div>

                            <div class="grid-2">
                                <div class="stat-box">
                                    <div class="stat-title">Image Composite Risk Index</div>
                                    <div class="stat-value" id="ocrRiskScore">0 / 100</div>
                                </div>
                                <div class="stat-box">
                                    <div class="stat-title">Threat Taxonomy Classification</div>
                                    <div class="stat-value" style="font-size:16px; margin-top:6px;" id="ocrScamType">-</div>
                                </div>
                            </div>

                            <h4 style="margin: 16px 0 10px 0; color:#f8fafc; font-size:13px; text-transform:uppercase; letter-spacing:0.5px;">
                                🧠 Psychological Manipulation Meter:
                            </h4>
                            <div class="grid-2">
                                <div class="stat-box">
                                    <div class="stat-title">Urgency Pressure: <span id="ocrValUrgency" style="color:#38bdf8;">0%</span></div>
                                    <div class="meter-bar"><div id="ocrBarUrgency" class="meter-fill"></div></div>
                                </div>
                                <div class="stat-box">
                                    <div class="stat-title">Fear / Coercion: <span id="ocrValFear" style="color:#f43f5e;">0%</span></div>
                                    <div class="meter-bar"><div id="ocrBarFear" class="meter-fill" style="background:#f43f5e;"></div></div>
                                </div>
                                <div class="stat-box">
                                    <div class="stat-title">Reward / Greed: <span id="ocrValReward" style="color:#f59e0b;">0%</span></div>
                                    <div class="meter-bar"><div id="ocrBarReward" class="meter-fill" style="background:#f59e0b;"></div></div>
                                </div>
                                <div class="stat-box">
                                    <div class="stat-title">Authority Impersonation: <span id="ocrValAuthority" style="color:#a855f7;">0%</span></div>
                                    <div class="meter-bar"><div id="ocrBarAuthority" class="meter-fill" style="background:#a855f7;"></div></div>
                                </div>
                            </div>

                            <!-- OCR SHAP CARD -->
                            <div id="ocrShapCard" style="display:none; margin-top:16px; background:#070c18; padding:16px; border-radius:12px; border:1px solid #1e293b;">
                                <h4 style="margin:0 0 10px 0; color:#38bdf8; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">
                                    🧠 Explainable AI (SHAP Threat Attribution):
                                </h4>
                                <div id="ocrShapSummary" style="font-size:13px; color:#e2e8f0; line-height:1.6; margin-bottom:12px; padding:10px; background:rgba(255,255,255,0.03); border-radius:8px; border-left:3px solid #38bdf8;"></div>
                                
                                <div id="ocrShapUrlBox" style="display:none; margin-bottom:10px;">
                                    <div style="font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-bottom:6px;">Extracted URL / QR Risk Drivers (TreeExplainer):</div>
                                    <div id="ocrShapUrlList" style="display:flex; flex-direction:column; gap:6px;"></div>
                                </div>

                                <div id="ocrShapTextBox" style="margin-bottom:6px;">
                                    <div style="font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-bottom:6px;">Optical Text Risk Drivers (NLP Attributions):</div>
                                    <div id="ocrShapWordsList" style="display:flex; flex-direction:column; gap:6px;"></div>
                                </div>
                            </div>

                            <h4 style="margin: 18px 0 8px 0; color:#f8fafc; font-size:13px; text-transform:uppercase; letter-spacing:0.5px;">
                                🚨 National Citizen Defense & Helpline Escalation:
                            </h4>
                            <div class="advice-card" id="ocrAdviceSummary"></div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- TAB 2: HUNT MODE -->
            <section id="pane-hunt" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <h2 class="card-title">🎯 Autonomous Threat Feed Hunter</h2>
                            <p class="card-desc">Sweeps live public feeds (OpenPhish, URLhaus) and crt.sh brand lookalike domains to intercept scams BEFORE distribution.</p>
                        </div>
                        <div style="display:flex; gap:10px;">
                            <button id="btnRunHunt" class="btn-scan-primary" style="padding:10px 18px;" onclick="executeHuntScan()">
                                <span>🚀 Run Live Feed Hunter</span>
                            </button>
                            <button class="btn-clear-ghost" style="padding:10px 16px;" onclick="exportBlocklist()">
                                <span>📥 Export Blocklist (.JSON)</span>
                            </button>
                        </div>
                    </div>

                    <div id="huntResultsTableWrapper" style="display:none; margin-top:10px;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Target URL / Host</th>
                                    <th>Threat Feed Source</th>
                                    <th>Risk Index</th>
                                    <th>Verdict</th>
                                    <th>Taxonomy</th>
                                    <th>Defensive Action</th>
                                </tr>
                            </thead>
                            <tbody id="huntTableBody"></tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- TAB 3: INCIDENT AUDIT LOGS -->
            <section id="pane-logs" class="tab-content">
                <div class="grid-4">
                    <div class="stat-box">
                        <div class="stat-title">Total Interceptions</div>
                        <div class="stat-value" id="kpiTotal">0</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-title">Confirmed Blocked</div>
                        <div class="stat-value" style="color:var(--red);" id="kpiBlocked">0</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-title">Under Review (Hold)</div>
                        <div class="stat-value" style="color:var(--yellow);" id="kpiHeld">0</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-title">Average Risk Score</div>
                        <div class="stat-value" id="kpiAvgRisk">0.0</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <div>
                            <h2 class="card-title">📊 Incident Audit Trail (SQLite)</h2>
                            <p class="card-desc">Tamper-evident log of all intercepted messages and URLs with risk scoring records.</p>
                        </div>
                        <button class="btn-clear-ghost" style="padding:7px 14px; font-size:12px;" onclick="fetchAuditLogs()">🔄 Refresh</button>
                    </div>

                    <div style="margin-bottom:12px;">
                        <input type="text" id="logSearchInput" placeholder="Filter audit logs by keyword, domain, or scam type..." oninput="filterLogs()">
                    </div>

                    <div style="overflow-x:auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Content Snippet</th>
                                    <th>URL Target</th>
                                    <th>Risk Score</th>
                                    <th>Verdict</th>
                                    <th>Taxonomy</th>
                                </tr>
                            </thead>
                            <tbody id="auditTableBody">
                                <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Loading audit trail...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- TAB 4: API HUB (B2B WEBSITE X SCAM SHIELD) -->
            <section id="pane-api" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
                                <h2 class="card-title">⚡ B2B Fraud Protection Hub (Website X Shield)</h2>
                                <span style="font-size:11px; font-weight:700; background:rgba(16,185,129,0.15); color:#34d399; padding:2px 8px; border-radius:6px; border:1px solid rgba(16,185,129,0.3);">
                                    Active Pre-Publish Enforcement
                                </span>
                            </div>
                            <p class="card-desc">
                                When external <b>"Website X"</b> (social platforms, classifieds, messaging apps, payment portals) receives user posts, messages, or image uploads, they call FraudShield's REST API. FraudShield inspects the payload and returns an authoritative directive: <b>DEMAND TO BLOCK IMMEDIATELY (HTTP 403)</b> or <b>AUTHORIZE PUBLICATION (HTTP 200)</b>.
                            </p>
                        </div>
                        <button class="btn-scan-primary" style="padding:9px 16px;" onclick="window.open('/docs', '_blank')">
                            <span>📖 Interactive Swagger Docs</span>
                        </button>
                    </div>

                    <!-- LIVE EXTERNAL INTEGRATION: WEBSITE X STANDALONE APP -->
                    <div style="background:linear-gradient(135deg, rgba(245,158,11,0.12), rgba(56,189,248,0.08)); border:1px solid rgba(245,158,11,0.35); border-radius:12px; padding:18px; margin-bottom:20px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                            <div style="display:flex; align-items:center; gap:12px;">
                                <div style="font-size:32px; background:rgba(245,158,11,0.15); border:1px solid rgba(245,158,11,0.4); width:50px; height:50px; border-radius:12px; display:flex; align-items:center; justify-content:center;">
                                    🛒
                                </div>
                                <div>
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <h3 style="font-size:16px; font-weight:800; color:#fff;">Live External Client: Website X (QuickPost Marketplace)</h3>
                                        <span style="font-size:11px; font-weight:700; background:rgba(16,185,129,0.2); color:#34d399; padding:2px 8px; border-radius:999px; border:1px solid rgba(16,185,129,0.4);">
                                            ● Live on Port 5000
                                        </span>
                                    </div>
                                    <p style="font-size:12px; color:#cbd5e1; margin-top:4px; max-width:650px; line-height:1.4;">
                                        We have deployed a real, standalone e-commerce and classifieds marketplace running on <b>http://127.0.0.1:5000</b>. Whenever a user submits a listing on Website X, its backend calls FraudShield AI in real-time. If scam content or rogue flyers are detected, FraudShield orders Website X to reject the post with HTTP 403 Forbidden!
                                    </p>
                                </div>
                            </div>
                            <div style="display:flex; gap:10px;">
                                <button type="button" class="btn-scan-primary" style="background:linear-gradient(135deg, #f59e0b, #d97706); color:#0b1120; font-weight:800; padding:10px 18px;" onclick="window.open('http://127.0.0.1:5000', '_blank')">
                                    <span>🚀 Open External Website X (Port 5000) ↗</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- API GATEWAY CREDENTIALS & KEYS -->
                    <div class="grid-2" style="margin-bottom:20px;">
                        <div style="background:#080d1a; border:1px solid var(--border); border-radius:10px; padding:14px;">
                            <div style="font-size:11px; font-weight:700; color:#38bdf8; text-transform:uppercase; margin-bottom:6px;">
                                🌐 REST API Gateway Endpoint:
                            </div>
                            <div style="display:flex; justify-content:space-between; align-items:center; background:#040711; border:1px solid var(--border); border-radius:6px; padding:8px 12px;">
                                <code style="font-size:12px; color:#f8fafc; font-family:'JetBrains Mono',monospace;">POST http://127.0.0.1:8000/api/v1/protect</code>
                                <button type="button" class="btn-clear-ghost" style="padding:2px 8px; font-size:11px; color:#38bdf8;" onclick="navigator.clipboard.writeText('http://127.0.0.1:8000/api/v1/protect'); alert('API Endpoint copied!');">Copy</button>
                            </div>
                        </div>

                        <div style="background:#080d1a; border:1px solid var(--border); border-radius:10px; padding:14px;">
                            <div style="font-size:11px; font-weight:700; color:#10b981; text-transform:uppercase; margin-bottom:6px;">
                                🔑 Active Production API Key:
                            </div>
                            <div style="display:flex; justify-content:space-between; align-items:center; background:#040711; border:1px solid var(--border); border-radius:6px; padding:8px 12px;">
                                <code style="font-size:12px; color:#a7f3d0; font-family:'JetBrains Mono',monospace;">fs_live_sec_8f92a10b4c81</code>
                                <button type="button" class="btn-clear-ghost" style="padding:2px 8px; font-size:11px; color:#10b981;" onclick="navigator.clipboard.writeText('fs_live_sec_8f92a10b4c81'); alert('API Key copied!');">Copy</button>
                            </div>
                        </div>
                    </div>



                    <!-- DEVELOPER INTEGRATION GUIDES -->
                    <h3 style="margin: 20px 0 10px 0; color:#f8fafc; font-size:15px; font-weight:700;">
                        🛠️ How Website X Enforces This in Code (Copy-Paste Middleware)
                    </h3>

                    <!-- Python Middleware -->
                    <h4 style="margin: 12px 0 6px 0; color:#38bdf8; font-size:12px; text-transform:uppercase;">
                        1. Python (Flask / FastAPI Middleware for Website X):
                    </h4>
                    <div class="code-box">import requests
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

@app.middleware("http")
async def fraudshield_security_guard(request: Request, call_next):
    # Intercept user posts, messages, or comments before saving
    if request.method == "POST" and request.url.path.startswith("/api/posts"):
        body = await request.json()
        
        # 1. Ask FraudShield AI to inspect the payload
        res = requests.post("http://127.0.0.1:8000/api/v1/protect", json={
            "client_id": "Website-X-Production",
            "text": body.get("content", ""),
            "url": body.get("link", ""),
            "image_base64": body.get("attachment_base64", "")
        }).json()
        
        # 2. Enforce FraudShield's blocking directive immediately
        if res.get("action_demanded") == "BLOCK_IMMEDIATELY":
            print("🚨 BLOCKED BY FRAUDSHIELD:", res["enforcement_directive"])
            raise HTTPException(
                status_code=403, 
                detail={
                    "error": "CONTENT_BLOCKED_BY_FRAUDSHIELD",
                    "reason": res["suggested_http_response"]["client_body"]["reason"],
                    "scan_id": res["scan_id"]
                }
            )
            
    return await call_next(request)</div>

                    <!-- Node.js / Express Middleware -->
                    <h4 style="margin: 16px 0 6px 0; color:#38bdf8; font-size:12px; text-transform:uppercase;">
                        2. Node.js (Express Middleware for Website X):
                    </h4>
                    <div class="code-box">const axios = require('axios');

// Express Middleware for Website X
async function fraudShieldPrePublishGuard(req, res, next) {
    try {
        const { text, url, image_base64 } = req.body;

        // Query FraudShield Protection API
        const response = await axios.post('http://127.0.0.1:8000/api/v1/protect', {
            client_id: 'Website-X-NodeJS',
            text, url, image_base64
        });

        const shield = response.data;

        // If FraudShield demands an immediate block, reject the HTTP request with 403
        if (shield.action_demanded === 'BLOCK_IMMEDIATELY') {
            console.error('🛑 FraudShield Block Demanded:', shield.enforcement_directive);
            return res.status(403).json({
                error: 'SUBMISSION_REJECTED',
                message: 'Post rejected by automated cyber safety filter.',
                directive: shield.enforcement_directive,
                reasons: shield.threat_analysis.reasons
            });
        }

        // Clean content: proceed with normal handling
        next();
    } catch (err) {
        console.error('FraudShield guard error:', err.message);
        next();
    }
}

app.post('/api/submit-post', fraudShieldPrePublishGuard, (req, res) => {
    res.json({ success: true, message: 'Post published safely!' });
});</div>

                    <!-- cURL Integration -->
                    <h4 style="margin: 16px 0 6px 0; color:#38bdf8; font-size:12px; text-transform:uppercase;">
                        3. cURL Integration:
                    </h4>
                    <div class="code-box">curl -X POST "http://127.0.0.1:8000/api/v1/protect" \\
     -H "Content-Type: application/json" \\
     -d '{
       "client_id": "Website-X-Production",
       "text": "Your bank account is hacked! Click http://sbi-kyc-update.xyz immediately to unfreeze.",
       "url": "http://sbi-kyc-update.xyz"
     }'</div>
                </div>
            </section>
        </main>

        <!-- AUTHENTICATION MODAL (LOGIN & REGISTER) -->
        <div id="authModal" class="modal-overlay">
            <div class="modal-window">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                    <h3 style="font-size:18px; font-weight:800; color:#fff;" id="modalTitle">🔐 Account Portal</h3>
                    <button style="background:none; border:none; color:var(--text-muted); font-size:22px; cursor:pointer;" onclick="closeAuthModal()">&times;</button>
                </div>

                <div class="modal-tabs">
                    <button id="tabBtnLogin" class="modal-tab-btn active" onclick="setAuthMode('login')">Sign In</button>
                    <button id="tabBtnRegister" class="modal-tab-btn" onclick="setAuthMode('register')">Sign Up / Register</button>
                </div>

                <div id="authAlertBox" class="alert-box"></div>

                <!-- SIGN IN FORM -->
                <div id="formSignIn">
                    <label class="form-label">Email Address or Phone Number:</label>
                    <input type="text" id="loginIdentifier" placeholder="Enter your email or phone number" autocomplete="username">

                    <label class="form-label">Password:</label>
                    <div class="password-wrapper">
                        <input type="password" id="loginPassword" placeholder="Enter your password" autocomplete="current-password">
                        <button type="button" class="btn-toggle-pass" onclick="togglePasswordVisibility('loginPassword', this)" title="Show password" aria-label="Toggle password visibility">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                    </div>

                    <button class="btn-scan-primary" style="width:100%; margin-top:8px;" onclick="submitLoginAuth()">Sign In</button>
                </div>

                <!-- REGISTER FORM -->
                <div id="formRegister" style="display:none;">
                    <label class="form-label">Full Name:</label>
                    <input type="text" id="regName" placeholder="Enter your full name" autocomplete="name">

                    <label class="form-label">Email ID:</label>
                    <input type="email" id="regEmail" placeholder="Enter your email address" autocomplete="email">

                    <label class="form-label">Mobile Phone Number:</label>
                    <input type="tel" id="regPhone" placeholder="Enter your mobile phone number" autocomplete="tel">

                    <label class="form-label">College / Organization / Team:</label>
                    <input type="text" id="regOrg" placeholder="Enter your college or team name">

                    <label class="form-label">Create Password:</label>
                    <div class="password-wrapper">
                        <input type="password" id="regPassword" placeholder="Create your account password" autocomplete="new-password">
                        <button type="button" class="btn-toggle-pass" onclick="togglePasswordVisibility('regPassword', this)" title="Show password" aria-label="Toggle password visibility">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                    </div>

                    <button class="btn-scan-primary" style="width:100%; margin-top:6px;" onclick="submitRegisterAuth()">Sign Up / Register</button>
                </div>
            </div>
        </div>

        <!-- PROFILE DRAWER / MODAL -->
        <div id="profileModal" class="modal-overlay">
            <div class="modal-window">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                    <h3 style="font-size:18px; font-weight:800; color:#fff;">👤 User Account</h3>
                    <button style="background:none; border:none; color:var(--text-muted); font-size:22px; cursor:pointer;" onclick="closeProfileModal()">&times;</button>
                </div>

                <div style="text-align:center; margin-bottom:20px;">
                    <div style="width:60px; height:60px; border-radius:50%; background:linear-gradient(135deg, #10b981, #0284c7); display:flex; align-items:center; justify-content:center; font-size:24px; font-weight:800; color:#fff; margin:0 auto 10px auto;" id="profCardAvatar">K</div>
                    <h3 style="color:#fff; font-size:18px;" id="profCardName">Karthik V.</h3>
                    <div style="font-size:12px; color:var(--accent); font-weight:700;" id="profCardOrg">Team Hackscribe (CSE)</div>
                </div>

                <div style="background:#080d1a; border:1px solid var(--border); border-radius:10px; padding:14px; font-size:13px; line-height:1.8; margin-bottom:20px;">
                    <div><b>Organization:</b> <span id="profCardOrgDetail" style="color:#cbd5e1;">Team Hackscribe (CSE)</span></div>
                    <div><b>Email:</b> <span id="profCardEmail" style="color:#cbd5e1;">karthik@hackscribe.dev</span></div>
                    <div><b>Phone:</b> <span id="profCardPhone" style="color:#cbd5e1;">+91 98765 43210</span></div>
                    <div><b>Status:</b> <span style="color:#34d399; font-weight:700;">Active Developer / Participant</span></div>
                </div>

                <button class="btn-clear-ghost" style="width:100%; color:#f43f5e; border-color:#f43f5e44;" onclick="logoutUserSession()">Sign Out</button>
            </div>
        </div>

        <script>
            // CURRENT AUTH SESSION STATE
            let currentUser = null;
            let rawIncidentList = [];
            let latestHuntedThreats = [];

            // TABS NAVIGATION
            function switchNavTab(tabId) {
                document.querySelectorAll('.nav-tab-btn').forEach(btn => btn.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(pane => pane.classList.remove('active'));

                const targetBtn = document.querySelector(`.nav-tab-btn[onclick*="'${tabId}'"]`) ||
                                  Array.from(document.querySelectorAll('.nav-tab-btn')).find(b => b.innerText.toLowerCase().includes(tabId));
                if (targetBtn) targetBtn.classList.add('active');

                const targetPane = document.getElementById('pane-' + tabId);
                if (targetPane) targetPane.classList.add('active');

                if (tabId === 'logs') fetchAuditLogs();
            }

            // MODALS
            function openAuthModal() {
                document.getElementById('authModal').style.display = 'flex';
                document.getElementById('authAlertBox').style.display = 'none';
                setAuthMode('login');
            }
            function closeAuthModal() {
                document.getElementById('authModal').style.display = 'none';
            }
            function setAuthMode(mode) {
                document.getElementById('authAlertBox').style.display = 'none';
                if (mode === 'login') {
                    document.getElementById('tabBtnLogin').classList.add('active');
                    document.getElementById('tabBtnRegister').classList.remove('active');
                    document.getElementById('formSignIn').style.display = 'block';
                    document.getElementById('formRegister').style.display = 'none';
                    document.getElementById('modalTitle').innerText = '🔐 Sign In';
                } else {
                    document.getElementById('tabBtnLogin').classList.remove('active');
                    document.getElementById('tabBtnRegister').classList.add('active');
                    document.getElementById('formSignIn').style.display = 'none';
                    document.getElementById('formRegister').style.display = 'block';
                    document.getElementById('modalTitle').innerText = '📝 Sign Up / Register';
                }
            }

            function togglePasswordVisibility(inputId, btn) {
                const input = document.getElementById(inputId);
                if (!input) return;
                if (input.type === 'password') {
                    input.type = 'text';
                    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
                    btn.title = "Hide password";
                } else {
                    input.type = 'password';
                    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
                    btn.title = "Show password";
                }
            }

            async function submitLoginAuth() {
                const identifier = document.getElementById('loginIdentifier').value.trim();
                const password = document.getElementById('loginPassword').value.trim();

                if (!identifier || !password) {
                    showAuthAlert('Please enter both Email/Phone and Password.');
                    return;
                }

                try {
                    const res = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ identifier, password })
                    });
                    const data = await res.json();
                    if (res.ok && data.authenticated) {
                        applyUserSession(data.user);
                        closeAuthModal();
                    } else {
                        showAuthAlert(data.error || 'Authentication failed.');
                    }
                } catch(e) {
                    showAuthAlert('Network error connecting to auth service.');
                }
            }

            async function submitRegisterAuth() {
                const name = document.getElementById('regName').value.trim();
                const email = document.getElementById('regEmail').value.trim();
                const phone = document.getElementById('regPhone').value.trim();
                const organization = document.getElementById('regOrg').value.trim();
                const password = document.getElementById('regPassword').value.trim();

                if (!name || !email || !phone || !password) {
                    showAuthAlert('Name, Email, Phone, and Password are required.');
                    return;
                }

                try {
                    const res = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ name, email, phone, organization, password })
                    });
                    const data = await res.json();
                    if (res.ok && data.registered) {
                        applyUserSession(data.user);
                        closeAuthModal();
                    } else {
                        showAuthAlert(data.error || 'Registration failed.');
                    }
                } catch(e) {
                    showAuthAlert('Network error connecting to registration service.');
                }
            }

            function showAuthAlert(msg) {
                const b = document.getElementById('authAlertBox');
                b.innerText = '⚠️ ' + msg;
                b.style.display = 'block';
            }

            function applyUserSession(user) {
                currentUser = user;
                try { localStorage.setItem('fraudshield_user', JSON.stringify(user)); } catch(e){}
                document.getElementById('btnOpenAuth').style.display = 'none';
                const pill = document.getElementById('userProfilePill');
                pill.style.display = 'flex';
                document.getElementById('badgeUserName').innerText = user.name;
                document.getElementById('badgeUserOrg').innerText = user.organization || 'Team Hackscribe';
                document.getElementById('avatarLetter').innerText = (user.name || 'U').charAt(0).toUpperCase();

                // Profile Modal update
                document.getElementById('profCardAvatar').innerText = (user.name || 'U').charAt(0).toUpperCase();
                document.getElementById('profCardName').innerText = user.name;
                document.getElementById('profCardOrg').innerText = user.organization || 'Team Hackscribe (CSE)';
                document.getElementById('profCardOrgDetail').innerText = user.organization || 'Team Hackscribe (CSE)';
                document.getElementById('profCardEmail').innerText = user.email;
                document.getElementById('profCardPhone').innerText = user.phone;
            }

            function openProfileModal() {
                document.getElementById('profileModal').style.display = 'flex';
            }
            function closeProfileModal() {
                document.getElementById('profileModal').style.display = 'none';
            }
            function logoutUserSession() {
                currentUser = null;
                try { localStorage.removeItem('fraudshield_user'); } catch(e){}
                document.getElementById('btnOpenAuth').style.display = 'flex';
                document.getElementById('userProfilePill').style.display = 'none';
                closeProfileModal();
            }

            // TEST PRESETS
            const PRESET_DATA = {
                electricity: {
                    text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your bill is unpaid. Contact power helpline immediately on 9823123456.",
                    url: "http://192.168.1.50/pay-bill.php"
                },
                sbi_kyc: {
                    text: "URGENT: Your SBI bank account will be suspended within 24 hours. Update your PAN Card immediately to avoid deactivation.",
                    url: "http://sbi-kyc-update.xyz/login.php"
                },
                lottery: {
                    text: "Congratulations! You have won Rs 25,00,000 in KBC Lucky Draw 2026. Send your processing fee of Rs 500 to claim prize immediately.",
                    url: "https://bit.ly/claim-kbc-cash"
                },
                legit: {
                    text: "Hi Priya, the CSE seminar presentation is scheduled for tomorrow at 10 AM in Lab 3. Please bring your laptop.",
                    url: "https://www.google.com"
                },
                phish_url: {
                    text: "",
                    url: "http://secure-hdfc-netbanking.top/update.html"
                }
            };
            function loadTestPreset(key) {
                hideScanAlert();
                const p = PRESET_DATA[key];
                document.getElementById('txtMessage').value = p.text;
                document.getElementById('txtUrl').value = p.url;
                executeFraudScan();
            }
            function showScanAlert(msg) {
                const b = document.getElementById('scanAlertBox');
                b.innerText = '⚠️ ' + msg;
                b.style.display = 'block';
            }
            function hideScanAlert() {
                document.getElementById('scanAlertBox').style.display = 'none';
            }
            function resetPreventForm() {
                document.getElementById('txtMessage').value = '';
                document.getElementById('txtUrl').value = '';
                document.getElementById('scanResultContainer').style.display = 'none';
                hideScanAlert();
            }

            // SCAN EXECUTION
            async function executeFraudScan() {
                hideScanAlert();
                const text = document.getElementById('txtMessage').value.trim();
                const url = document.getElementById('txtUrl').value.trim();
                const btn = document.getElementById('btnExecuteScan');
                const container = document.getElementById('scanResultContainer');

                if (!text && !url) {
                    showScanAlert('Both input fields are empty! Please enter a message or a URL before scanning.');
                    container.style.display = 'none';
                    return;
                }

                btn.disabled = true;
                btn.innerHTML = '<span class="spinner-icon"></span> Analyzing Threat Vectors...';

                try {
                    const res = await fetch('/api/prevent', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text, url })
                    });
                    const data = await res.json();

                    if (!res.ok) {
                        showScanAlert(data.error || 'Threat evaluation error.');
                        btn.disabled = false;
                        btn.innerHTML = '<span>🛡️ Scan Threat Vectors</span>';
                        return;
                    }

                    container.style.display = 'block';

                    const banner = document.getElementById('verdictBanner');
                    banner.className = 'verdict-banner verdict-' + data.verdict;
                    banner.innerText = 'VERDICT: ' + data.verdict + ' (' + data.risk_tier + ' RISK INDEX)';

                    document.getElementById('resRiskScore').innerText = data.risk_score + ' / 100';
                    document.getElementById('resScamType').innerText = data.scam_type;

                    const mm = data.manipulation_meter;
                    document.getElementById('valUrgency').innerText = mm.urgency + '%';
                    document.getElementById('barUrgency').style.width = mm.urgency + '%';

                    document.getElementById('valFear').innerText = mm.fear + '%';
                    document.getElementById('barFear').style.width = mm.fear + '%';

                    document.getElementById('valReward').innerText = mm.reward + '%';
                    document.getElementById('barReward').style.width = mm.reward + '%';

                    document.getElementById('valAuthority').innerText = mm.authority + '%';
                    document.getElementById('barAuthority').style.width = mm.authority + '%';

                    // Sandbox
                    const sandboxCard = document.getElementById('sandboxCard');
                    const sandboxSummary = document.getElementById('sandboxSummary');
                    if (data.sandbox_inspection) {
                        sandboxCard.style.display = 'block';
                        const sb = data.sandbox_inspection;
                        let html = `<div><b>Status:</b> ${sb.status} | <b>Title:</b> ${sb.title || 'N/A'}</div>`;
                        if (sb.has_password_field) {
                            html += `<div style="color:#fb7185; margin-top:4px;">⚠️ <b>Credential Trap:</b> Password input field detected on unverified page</div>`;
                        }
                        if (sb.harvesting_fields && sb.harvesting_fields.length > 0) {
                            html += `<div style="color:#fb7185; margin-top:4px;">🚨 <b>Harvesting Fields:</b> ${sb.harvesting_fields.join(', ')}</div>`;
                        }
                        if (sb.brand_mismatch) {
                            html += `<div style="color:#fb7185; margin-top:4px;">🚨 <b>Brand Spoofing:</b> ${sb.brand_mismatch}</div>`;
                        }
                        if (sb.note) {
                            html += `<div style="color:#94a3b8; margin-top:4px; font-size:12px;">ℹ️ ${sb.note}</div>`;
                        }
                        sandboxSummary.innerHTML = html;
                    } else {
                        sandboxCard.style.display = 'none';
                    }

                    // Threat flags
                    const flagsCard = document.getElementById('urlFlagsCard');
                    const flagsList = document.getElementById('urlFlagsList');
                    if (data.url_flags && data.url_flags.length > 0) {
                        flagsCard.style.display = 'block';
                        flagsList.innerHTML = data.url_flags.map(f => `<li>${f}</li>`).join('');
                    } else {
                        flagsCard.style.display = 'none';
                        flagsList.innerHTML = '';
                    }

                    // Explainable AI (SHAP)
                    if (data.explainability) {
                        renderShapCard(data.explainability);
                    }

                    document.getElementById('adviceSummary').innerText = data.safe_action_advice;
                    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

                } catch(e) {
                    showScanAlert('Network error connecting to FraudShield server.');
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = '<span>🛡️ Scan Threat Vectors</span>';
                }
            }

            // EXPLAINABLE AI (SHAP) RENDERER
            function renderShapCard(exp, prefix = '') {
                const card = document.getElementById(prefix ? prefix + 'ShapCard' : 'shapCard');
                if (!card) return;
                if (!exp || exp.error) {
                    card.style.display = 'none';
                    return;
                }
                card.style.display = 'block';

                const execEl = document.getElementById(prefix ? prefix + 'ShapSummary' : 'shapExecutiveSummary');
                if (execEl) {
                    const bullets = exp.executive_summary || [];
                    execEl.innerHTML = bullets.map(b => `<div>• ${b}</div>`).join('') || 'Neural and structural features analyzed.';
                }

                // URL SHAP Factors
                const urlBox = document.getElementById(prefix ? prefix + 'ShapUrlBox' : 'shapUrlBox');
                const urlList = document.getElementById(prefix ? prefix + 'ShapUrlList' : 'shapUrlList');
                if (urlList && urlBox) {
                    const uExp = exp.url_explainability;
                    if (uExp && uExp.features && uExp.features.length > 0) {
                        urlBox.style.display = 'block';
                        urlList.innerHTML = uExp.features.slice(0, 5).map(f => {
                            const isFraud = f.direction === 'FRAUD_DRIVER';
                            const badgeClass = isFraud ? 'shap-badge-fraud' : 'shap-badge-safe';
                            const sign = f.shap_value > 0 ? '+' : '';
                            return `
                                <div class="shap-item">
                                    <span class="shap-name" title="${f.label}">${f.label}</span>
                                    <span class="${badgeClass}">${sign}${(f.shap_value * 100).toFixed(1)}%</span>
                                </div>
                            `;
                        }).join('');
                    } else {
                        urlBox.style.display = 'none';
                    }
                }

                // Text Token Attributions
                const textBox = document.getElementById(prefix ? prefix + 'ShapTextBox' : 'shapTextBox');
                const textList = document.getElementById(prefix ? prefix + 'ShapWordsList' : 'shapTextList');
                if (textList) {
                    const tExp = exp.text_explainability;
                    if (tExp && tExp.tokens && tExp.tokens.length > 0) {
                        if (textBox) textBox.style.display = 'block';
                        textList.innerHTML = tExp.tokens.slice(0, 5).map(t => {
                            const isFraud = t.direction === 'FRAUD_DRIVER';
                            const badgeClass = isFraud ? 'shap-badge-fraud' : 'shap-badge-safe';
                            const sign = t.importance > 0 ? '+' : '';
                            return `
                                <div class="shap-item">
                                    <span class="shap-name">"${t.token}"</span>
                                    <span class="${badgeClass}">${sign}${t.percentage}%</span>
                                </div>
                            `;
                        }).join('');
                    } else {
                        if (textBox) textBox.style.display = 'none';
                        textList.innerHTML = '<div style="font-size:12px; color:#64748b;">No high-impact tokens extracted.</div>';
                    }
                }
            }

            // UNIVERSAL IMAGE THREAT ANALYZER (STEP 7)
            function handleOcrFileSelected(file) {
                if (!file) return;
                const reader = new FileReader();
                reader.onload = function(e) {
                    uploadOcrImage(e.target.result);
                };
                reader.readAsDataURL(file);
            }

            async function loadPresetSample(presetKey) {
                const names = {
                    'electricity': 'Electricity Cut Notice Flyer',
                    'sbi': 'SBI Account Frozen KYC Screenshot',
                    'upi_qr': 'KBC Lottery UPI QR Payment Scam',
                    'clean': 'Clean Campus Notice'
                };
                showOcrAlert('Loading sample: ' + (names[presetKey] || presetKey) + '...', false);
                try {
                    const res = await fetch('/api/image-sample?preset=' + encodeURIComponent(presetKey));
                    const data = await res.json();
                    if (res.ok && data.image_base64) {
                        uploadOcrImage(data.image_base64);
                    } else {
                        showOcrAlert('Could not load sample: ' + (data.error || 'file not found'));
                    }
                } catch(e) {
                    showOcrAlert('Network error loading sample image.');
                }
            }

            function loadSampleOcrPoster() {
                loadPresetSample('electricity');
            }

            async function uploadOcrImage(base64Data) {
                hideOcrAlert();
                const loading = document.getElementById('ocrLoading');
                const results = document.getElementById('ocrResultsWrapper');
                loading.style.display = 'block';
                results.style.display = 'none';

                try {
                    const res = await fetch('/api/image-scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ image_base64: base64Data })
                    });
                    const data = await res.json();
                    if (!res.ok || !data.success) {
                        showOcrAlert(data.error || 'Failed to process image threat scan.');
                        loading.style.display = 'none';
                        return;
                    }

                    renderOcrScanResult(data, base64Data);
                } catch(e) {
                    showOcrAlert('Network error connecting to Image Threat Analysis service.');
                } finally {
                    loading.style.display = 'none';
                }
            }

            function renderOcrScanResult(data, previewUrl) {
                const results = document.getElementById('ocrResultsWrapper');
                results.style.display = 'block';

                // 1. Preview, Category & Metadata
                document.getElementById('ocrPreviewImage').src = previewUrl;
                const meta = data.image_metadata || {};
                const catTag = document.getElementById('ocrCategoryTag');
                if (catTag) {
                    catTag.innerText = meta.image_category || 'Scanned Image';
                }
                const metaText = document.getElementById('ocrImageMetaText');
                if (metaText) {
                    metaText.innerText = `${meta.width || 0}×${meta.height || 0} px • ${meta.format || 'IMG'} • ${meta.lines_count || 0} optical text lines`;
                }

                // QR Code box
                const qrBox = document.getElementById('ocrQrCodeBox');
                const qr = data.qr_code;
                if (qr && qr.has_qr) {
                    qrBox.style.display = 'block';
                    document.getElementById('ocrQrTypeTitle').innerText = `📱 Embedded QR Code (${qr.type}):`;
                    document.getElementById('ocrQrPayloadText').innerText = qr.payload;
                } else if (qrBox) {
                    qrBox.style.display = 'none';
                }

                // 2. Extracted Text & Entities
                document.getElementById('ocrExtractedText').innerText = data.extracted_text || '(No optical text detected in image)';
                const entitiesBox = document.getElementById('ocrEntitiesBox');
                let entHtml = '';
                const entities = data.detected_entities || {};

                // Impersonated brands
                if (entities.impersonated_brands && entities.impersonated_brands.length > 0) {
                    entHtml += entities.impersonated_brands.map(b => `<span style="font-size:11px; background:rgba(168,85,247,0.15); color:#c084fc; padding:3px 8px; border-radius:6px; border:1px solid rgba(168,85,247,0.3);">🏛️ Brand: ${b}</span>`).join('');
                }
                // UPI IDs
                if (entities.upi_ids && entities.upi_ids.length > 0) {
                    entHtml += entities.upi_ids.map(u => `<span style="font-size:11px; background:rgba(234,179,8,0.15); color:#facc15; padding:3px 8px; border-radius:6px; border:1px solid rgba(234,179,8,0.3);">💳 UPI: ${u}</span>`).join('');
                }
                // Amounts
                if (entities.amounts && entities.amounts.length > 0) {
                    entHtml += entities.amounts.map(a => `<span style="font-size:11px; background:rgba(34,197,94,0.15); color:#4ade80; padding:3px 8px; border-radius:6px; border:1px solid rgba(34,197,94,0.3);">💰 Amount: ${a}</span>`).join('');
                }
                // Phone numbers
                const phones = entities.phones || data.detected_phones || [];
                if (phones.length > 0) {
                    entHtml += phones.map(p => `<span style="font-size:11px; background:rgba(244,63,94,0.15); color:#fb7185; padding:3px 8px; border-radius:6px; border:1px solid rgba(244,63,94,0.3);">📞 Phone: ${p}</span>`).join('');
                }
                // URLs
                const urls = entities.urls || data.detected_urls || [];
                if (urls.length > 0) {
                    entHtml += urls.map(u => `<span style="font-size:11px; background:rgba(56,189,248,0.15); color:#38bdf8; padding:3px 8px; border-radius:6px; border:1px solid rgba(56,189,248,0.3);">🔗 Link: ${u}</span>`).join('');
                }

                if (!entHtml) {
                    entHtml = '<span style="font-size:11px; color:#64748b;">No high-risk entities detected.</span>';
                }
                entitiesBox.innerHTML = entHtml;

                // 3. Risk Engine result
                const ra = data.risk_analysis;
                const banner = document.getElementById('ocrVerdictBanner');
                banner.className = 'verdict-banner verdict-' + ra.verdict;
                banner.innerText = 'IMAGE VERDICT: ' + ra.verdict + ' (' + ra.risk_tier + ' RISK INDEX)';

                // Brand Integrity Audit Box (Computer Vision Logo vs Domain / Payment / Contact)
                const auditBox = document.getElementById('ocrBrandAuditBox');
                const audit = data.brand_integrity_audit;
                if (auditBox) {
                    if (audit && audit.has_logo) {
                        auditBox.style.display = 'block';
                        const isMismatch = audit.mismatch_detected;
                        const borderColor = isMismatch ? 'rgba(244, 63, 94, 0.45)' : 'rgba(16, 185, 129, 0.45)';
                        const bgColor = isMismatch ? 'rgba(244, 63, 94, 0.08)' : 'rgba(16, 185, 129, 0.08)';
                        const titleColor = isMismatch ? '#fb7185' : '#34d399';
                        const icon = isMismatch ? '🚨' : '🛡️';

                        let logoBadges = (audit.detected_logos || []).map(l => 
                            `<span style="background:rgba(255,255,255,0.08); padding:3px 8px; border-radius:6px; font-weight:600; color:#f1f5f9; font-size:11px; border:1px solid rgba(255,255,255,0.15);">
                                🏷️ ${l.brand} (${Math.round((l.confidence || 0.9) * 100)}% match • ${l.detection_method || 'Vision Model'})
                            </span>`
                        ).join(' ');

                        let flagsList = '';
                        if (isMismatch && audit.flags && audit.flags.length > 0) {
                            flagsList = `<div style="margin-top:10px; display:flex; flex-direction:column; gap:6px;">` + 
                                audit.flags.map(f => `<div style="font-size:12px; color:#fecdd3; background:rgba(244,63,94,0.12); padding:6px 10px; border-radius:6px; border-left:3px solid #f43f5e; line-height:1.4;">${f}</div>`).join('') +
                                `</div>`;
                        } else if (!isMismatch) {
                            flagsList = `<div style="margin-top:8px; font-size:12px; color:#a7f3d0; background:rgba(16,185,129,0.1); padding:6px 10px; border-radius:6px; border-left:3px solid #10b981;">
                                Verified authentic digital footprint. The detected brand insignia matches authorized domains, handles, and verification records.
                            </div>`;
                        }

                        auditBox.style.border = `1px solid ${borderColor}`;
                        auditBox.style.background = bgColor;
                        auditBox.style.borderRadius = '10px';
                        auditBox.style.padding = '12px 14px';
                        auditBox.innerHTML = `
                            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                                <div style="font-size:12px; font-weight:800; color:${titleColor}; text-transform:uppercase; letter-spacing:0.5px;">
                                    ${icon} Visual Brand Integrity Audit: ${audit.integrity_verdict.replace(/_/g, ' ')}
                                </div>
                                <div style="display:flex; gap:6px; align-items:center;">
                                    ${logoBadges}
                                </div>
                            </div>
                            ${flagsList}
                        `;
                    } else {
                        auditBox.style.display = 'none';
                    }
                }

                document.getElementById('ocrRiskScore').innerText = ra.risk_score + ' / 100';
                document.getElementById('ocrScamType').innerText = ra.scam_type;

                const mm = ra.manipulation_meter || { urgency: 0, fear: 0, reward: 0, authority: 0 };
                document.getElementById('ocrValUrgency').innerText = mm.urgency + '%';
                document.getElementById('ocrBarUrgency').style.width = mm.urgency + '%';
                document.getElementById('ocrValFear').innerText = mm.fear + '%';
                document.getElementById('ocrBarFear').style.width = mm.fear + '%';
                document.getElementById('ocrValReward').innerText = mm.reward + '%';
                document.getElementById('ocrBarReward').style.width = mm.reward + '%';
                document.getElementById('ocrValAuthority').innerText = mm.authority + '%';
                document.getElementById('ocrBarAuthority').style.width = mm.authority + '%';

                // 4. SHAP Explainability for Image
                if (ra.explainability) {
                    renderShapCard(ra.explainability, 'ocr');
                } else {
                    const card = document.getElementById('ocrShapCard');
                    if (card) card.style.display = 'none';
                }

                document.getElementById('ocrAdviceSummary').innerText = ra.safe_action_advice;
                results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }

            function showOcrAlert(msg, isError = true) {
                const b = document.getElementById('ocrAlertBox');
                b.innerText = (isError ? '⚠️ ' : 'ℹ️ ') + msg;
                b.style.display = 'block';
            }
            function hideOcrAlert() {
                document.getElementById('ocrAlertBox').style.display = 'none';
            }

            // HUNT MODE
            async function executeHuntScan() {
                const btn = document.getElementById('btnRunHunt');
                const wrap = document.getElementById('huntResultsTableWrapper');
                const tbody = document.getElementById('huntTableBody');

                btn.disabled = true;
                btn.innerHTML = '<span class="spinner-icon"></span> Sweeping Feeds...';
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">Autonomous Threat Hunter scanning live feeds...</td></tr>';
                wrap.style.display = 'block';

                try {
                    const res = await fetch('/api/hunt?max_items=8');
                    const data = await res.json();
                    tbody.innerHTML = '';
                    latestHuntedThreats = data.threats;

                    data.threats.forEach(t => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#38bdf8;">${t.url.substring(0, 42)}...</td>
                            <td><span style="font-size:11px; background:#1e293b; padding:2px 6px; border-radius:4px;">${t.source}</span></td>
                            <td style="font-weight:700;">${t.risk_score}%</td>
                            <td><span class="badge-chip badge-${t.verdict}">${t.verdict}</span></td>
                            <td>${t.scam_type}</td>
                            <td style="color:#34d399; font-size:12px; font-weight:600;">${t.action_taken}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                } catch(e) {
                    tbody.innerHTML = '<tr><td colspan="6" style="color:#f43f5e; text-align:center;">Failed to sweep threat feeds.</td></tr>';
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = '<span>🚀 Run Live Feed Hunter</span>';
                }
            }

            function exportBlocklist() {
                if (!latestHuntedThreats || latestHuntedThreats.length === 0) {
                    alert('Please run a live hunt scan first before exporting.');
                    return;
                }
                const blocklistOnly = latestHuntedThreats.filter(t => t.verdict === 'BLOCK');
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(blocklistOnly, null, 2));
                const dl = document.createElement('a');
                dl.setAttribute("href", dataStr);
                dl.setAttribute("download", "fraudshield_blocklist_" + new Date().toISOString().slice(0,10) + ".json");
                document.body.appendChild(dl);
                dl.click();
                dl.remove();
            }

            // INCIDENT LOGS
            async function fetchAuditLogs() {
                try {
                    const res = await fetch('/api/incidents');
                    const data = await res.json();
                    rawIncidentList = data.incidents;

                    document.getElementById('kpiTotal').innerText = data.stats.total_scans;
                    document.getElementById('kpiBlocked').innerText = data.stats.blocked_threats;
                    document.getElementById('kpiHeld').innerText = data.stats.held_investigations;
                    document.getElementById('kpiAvgRisk').innerText = data.stats.avg_risk + ' / 100';

                    renderIncidentTable(rawIncidentList);
                } catch(e) {
                    console.error("Failed to load logs:", e);
                }
            }

            function renderIncidentTable(list) {
                const tbody = document.getElementById('auditTableBody');
                tbody.innerHTML = '';

                if (list.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No incident records logged yet. Run scans in Prevent Gate to populate!</td></tr>';
                    return;
                }

                list.forEach(inc => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-size:11px; color:#94a3b8;">${inc.timestamp}</td>
                        <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${inc.text || 'N/A'}</td>
                        <td style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#38bdf8;">${(inc.url || 'N/A').substring(0, 26)}</td>
                        <td style="font-weight:700;">${inc.risk_score}</td>
                        <td><span class="badge-chip badge-${inc.verdict}">${inc.verdict}</span></td>
                        <td style="font-size:12px;">${inc.scam_type}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            function filterLogs() {
                const q = document.getElementById('logSearchInput').value.toLowerCase();
                const filtered = rawIncidentList.filter(i => 
                    (i.text && i.text.toLowerCase().includes(q)) ||
                    (i.url && i.url.toLowerCase().includes(q)) ||
                    (i.scam_type && i.scam_type.toLowerCase().includes(q)) ||
                    (i.verdict && i.verdict.toLowerCase().includes(q))
                );
                renderIncidentTable(filtered);
            }

            // RESTORE USER SESSION OR SHOW SIGN IN
            window.addEventListener('DOMContentLoaded', () => {
                try {
                    const saved = localStorage.getItem('fraudshield_user');
                    if (saved) {
                        applyUserSession(JSON.parse(saved));
                    } else {
                        logoutUserSession();
                    }
                } catch(e) {
                    logoutUserSession();
                }

                // OCR Dropzone bindings
                const dz = document.getElementById('ocrDropzone');
                if (dz) {
                    ['dragenter', 'dragover'].forEach(name => {
                        dz.addEventListener(name, (e) => { e.preventDefault(); dz.classList.add('dragover'); }, false);
                    });
                    ['dragleave', 'drop'].forEach(name => {
                        dz.addEventListener(name, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }, false);
                    });
                    dz.addEventListener('drop', (e) => {
                        const dt = e.dataTransfer;
                        if (dt && dt.files && dt.files.length > 0) {
                            handleOcrFileSelected(dt.files[0]);
                        }
                    }, false);
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 65)
    print(f"[ONLINE] FraudShield AI Command Hub: http://127.0.0.1:{port}")
    print(f"API Documentation: http://127.0.0.1:{port}/docs")
    print("=" * 65)
    uvicorn.run("app:app", host=host, port=port, reload=False)
