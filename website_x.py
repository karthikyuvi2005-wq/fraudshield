import os
import json
import base64
import time
import urllib.request
import uvicorn
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

app = FastAPI(
    title="Website X - QuickPost Marketplace",
    description="Independent e-commerce & classifieds platform protected by FraudShield AI",
    version="1.0.0"
)

# FraudShield AI API Gateway Configuration
FRAUDSHIELD_API_URL = os.environ.get("FRAUDSHIELD_API_URL", "http://127.0.0.1:8000/api/v1/protect")
CLIENT_ID = "Website-X-QuickPostMarket"
API_KEY = "fs_live_sec_8f92a10b4c81"

# In-memory storage for published listings and security inspection logs
published_listings: List[Dict[str, Any]] = [
    {
        "id": 1,
        "title": "Solid Teak Wood Dining Table with 4 Chairs",
        "category": "Furniture",
        "price": "Rs. 6,500",
        "description": "Moving to another city, selling 2-year old solid teak dining table in excellent condition.",
        "image": "",
        "timestamp": "Today, 10:15 AM",
        "fraudshield_status": "VERIFIED_CLEAN",
        "risk_score": 14.2
    },
    {
        "id": 2,
        "title": "Dell UltraSharp 27-inch 4K Monitor",
        "category": "Electronics",
        "price": "Rs. 18,000",
        "description": "Original packaging with HDMI and DisplayPort cables. Used for work from home.",
        "image": "",
        "timestamp": "Today, 11:30 AM",
        "fraudshield_status": "VERIFIED_CLEAN",
        "risk_score": 8.5
    }
]

security_audit_logs: List[Dict[str, Any]] = []

class ListingRequest(BaseModel):
    title: str
    category: str
    price: Optional[str] = ""
    description: str
    link: Optional[str] = ""
    image_base64: Optional[str] = ""

@app.get("/api/listings")
def get_listings():
    return {"listings": published_listings, "total": len(published_listings)}

@app.get("/api/audit-logs")
def get_audit_logs():
    return {"logs": security_audit_logs, "total": len(security_audit_logs)}

@app.post("/api/publish")
async def publish_listing(payload: ListingRequest):
    """
    Website X Pre-Publish Security Gateway.
    Before adding any listing to the marketplace, Website X calls FraudShield AI's API.
    If FraudShield demands an immediate block, Website X enforces the directive and rejects the post with HTTP 403.
    """
    start_time = time.time()
    
    # 1. Prepare combined content for FraudShield inspection
    content_to_inspect = f"{payload.title}\n{payload.description}".strip()
    
    # 2. Call FraudShield AI API
    fs_request_data = {
        "client_id": CLIENT_ID,
        "text": content_to_inspect,
        "url": payload.link.strip() if payload.link else "",
        "image_base64": payload.image_base64.strip() if payload.image_base64 else "",
        "metadata": {
            "category": payload.category,
            "price": payload.price,
            "origin_site": "Website X (Port 5000)"
        }
    }
    
    try:
        req = urllib.request.Request(
            FRAUDSHIELD_API_URL,
            data=json.dumps(fs_request_data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-FraudShield-Key": API_KEY
            }
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            fs_response = json.loads(response.read().decode("utf-8"))
    except Exception as e:
        # Fallback if FraudShield server is unreachable
        return JSONResponse(
            status_code=503,
            content={
                "success": False,
                "error": f"FraudShield AI Security Gateway unreachable at {FRAUDSHIELD_API_URL}: {str(e)}"
            }
        )
        
    latency_ms = round((time.time() - start_time) * 1000, 1)
    
    is_threat = fs_response.get("is_threat", False)
    action_demanded = fs_response.get("action_demanded", "ALLOW_PUBLISH")
    enforcement_directive = fs_response.get("enforcement_directive", "")
    threat_analysis = fs_response.get("threat_analysis", {})
    risk_score = threat_analysis.get("risk_score", 0.0)
    reasons = threat_analysis.get("reasons", [])
    scan_id = fs_response.get("scan_id", "FS-N/A")
    
    # Log this security inspection inside Website X's audit trail
    audit_entry = {
        "scan_id": scan_id,
        "title": payload.title,
        "category": payload.category,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "latency_ms": latency_ms,
        "action_demanded": action_demanded,
        "is_threat": is_threat,
        "risk_score": risk_score,
        "reasons": reasons,
        "directive": enforcement_directive
    }
    security_audit_logs.insert(0, audit_entry)
    
    # 3. ENFORCE FRAUDSHIELD'S DIRECTIVE ON WEBSITE X
    if action_demanded == "BLOCK_IMMEDIATELY" or is_threat:
        # Website X rejects user submission immediately!
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "action": "BLOCKED",
                "demanded_by": "FraudShield AI Enterprise Gateway",
                "enforcement_directive": enforcement_directive,
                "risk_score": risk_score,
                "threat_type": threat_analysis.get("threat_type", "Cyber Threat"),
                "reasons": reasons,
                "scan_id": scan_id,
                "latency_ms": latency_ms,
                "user_message": "Submission rejected: Malicious cyber threat, phishing vector, or scam detected by automated pre-publish safety inspection."
            }
        )
    
    # 4. Clean content: Website X publishes the listing!
    new_listing = {
        "id": len(published_listings) + 1,
        "title": payload.title,
        "category": payload.category,
        "price": payload.price or "Contact Seller",
        "description": payload.description,
        "image": payload.image_base64,
        "timestamp": "Just now",
        "fraudshield_status": "VERIFIED_CLEAN",
        "risk_score": risk_score,
        "scan_id": scan_id
    }
    published_listings.insert(0, new_listing)
    
    return {
        "success": True,
        "action": "PUBLISHED",
        "listing": new_listing,
        "fraudshield_audit": {
            "risk_score": risk_score,
            "verdict": threat_analysis.get("verdict", "ALLOW"),
            "latency_ms": latency_ms,
            "scan_id": scan_id
        }
    }

# ----------------- WEBSITE X FRONTEND HTML -----------------
@app.get("/", response_class=HTMLResponse)
def website_x_ui():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛒 QuickPost Market (Website X) | Protected by FraudShield AI</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0b1120;
                --surface: #131c31;
                --card: #18233c;
                --border: #223254;
                --accent: #f59e0b;
                --blue: #38bdf8;
                --red: #f43f5e;
                --green: #10b981;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: 'Plus Jakarta Sans', sans-serif;
                background-color: var(--bg);
                color: var(--text-main);
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }
            .header-banner {
                background: linear-gradient(90deg, #1e293b, #0f172a);
                border-bottom: 2px solid var(--accent);
                padding: 14px 24px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 12px;
            }
            .brand-box {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .brand-logo {
                font-size: 26px;
                background: rgba(245, 158, 11, 0.15);
                border: 1px solid rgba(245, 158, 11, 0.4);
                border-radius: 10px;
                width: 44px;
                height: 44px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .brand-name {
                font-size: 20px;
                font-weight: 800;
                color: #fff;
                letter-spacing: -0.5px;
            }
            .brand-tag {
                font-size: 11px;
                color: var(--accent);
                font-weight: 600;
            }
            .shield-status-pill {
                display: flex;
                align-items: center;
                gap: 8px;
                background: rgba(16, 185, 129, 0.12);
                border: 1px solid rgba(16, 185, 129, 0.35);
                padding: 6px 14px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
                color: #34d399;
            }
            .pulse-dot {
                width: 8px;
                height: 8px;
                background: #10b981;
                border-radius: 50%;
                box-shadow: 0 0 8px #10b981;
                animation: pulse 2s infinite;
            }
            @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 24px 20px;
                width: 100%;
                flex: 1;
            }
            .grid-main {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 24px;
            }
            @media(max-width: 860px) { .grid-main { grid-template-columns: 1fr; } }

            .panel-card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 20px;
            }
            .panel-title {
                font-size: 16px;
                font-weight: 800;
                color: #fff;
                margin-bottom: 6px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .panel-desc {
                font-size: 12px;
                color: var(--text-muted);
                margin-bottom: 16px;
                line-height: 1.5;
            }

            .form-group {
                margin-bottom: 14px;
            }
            .form-label {
                display: block;
                font-size: 11px;
                font-weight: 700;
                color: #cbd5e1;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 5px;
            }
            .form-input, .form-textarea, .form-select {
                width: 100%;
                background: #090e1a;
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 10px 12px;
                color: #fff;
                font-size: 13px;
                font-family: inherit;
                outline: none;
                transition: border 0.2s;
            }
            .form-input:focus, .form-textarea:focus, .form-select:focus {
                border-color: var(--accent);
            }
            .form-textarea { height: 90px; resize: vertical; }

            .btn-publish {
                width: 100%;
                background: linear-gradient(135deg, #f59e0b, #d97706);
                color: #0b1120;
                font-weight: 800;
                font-size: 14px;
                padding: 12px 20px;
                border-radius: 10px;
                border: none;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                transition: transform 0.15s, box-shadow 0.15s;
            }
            .btn-publish:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 15px rgba(245, 158, 11, 0.4);
            }

            /* Attack Scenario Presets */
            .preset-bar {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 6px;
                margin-bottom: 14px;
                padding: 10px;
                background: #090e1a;
                border-radius: 10px;
                border: 1px solid var(--border);
            }
            .btn-preset {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.15);
                color: #cbd5e1;
                font-size: 11px;
                font-weight: 600;
                padding: 4px 9px;
                border-radius: 6px;
                cursor: pointer;
                transition: background 0.15s;
            }
            .btn-preset:hover { background: rgba(255,255,255,0.12); color: #fff; }
            .btn-preset-danger { border-color: rgba(244, 63, 94, 0.4); color: #fb7185; }
            .btn-preset-danger:hover { background: rgba(244, 63, 94, 0.15); }
            .btn-preset-clean { border-color: rgba(16, 185, 129, 0.4); color: #34d399; }
            .btn-preset-clean:hover { background: rgba(16, 185, 129, 0.15); }

            /* Decision Modals & Banners */
            .alert-banner {
                padding: 14px;
                border-radius: 10px;
                margin-bottom: 16px;
                display: none;
                animation: fadeIn 0.25s ease-out;
            }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
            .alert-blocked {
                background: rgba(244, 63, 94, 0.12);
                border: 1px solid #f43f5e;
                color: #fecdd3;
            }
            .alert-published {
                background: rgba(16, 185, 129, 0.12);
                border: 1px solid #10b981;
                color: #a7f3d0;
            }

            /* Live Listings Feed */
            .listing-card {
                background: #090e1a;
                border: 1px solid var(--border);
                border-radius: 10px;
                padding: 14px;
                margin-bottom: 12px;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
            .listing-top {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 10px;
            }
            .listing-title {
                font-size: 14px;
                font-weight: 700;
                color: #f8fafc;
            }
            .listing-price {
                font-size: 13px;
                font-weight: 800;
                color: var(--accent);
                white-space: nowrap;
            }
            .listing-meta {
                display: flex;
                gap: 8px;
                align-items: center;
                font-size: 11px;
                color: var(--text-muted);
            }
            .shield-verified-badge {
                background: rgba(16, 185, 129, 0.15);
                color: #34d399;
                border: 1px solid rgba(16, 185, 129, 0.3);
                border-radius: 4px;
                padding: 2px 6px;
                font-size: 10px;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 4px;
            }

            /* Audit Logs Table */
            .audit-table {
                width: 100%;
                border-collapse: collapse;
                font-size: 11px;
                margin-top: 10px;
            }
            .audit-table th {
                text-align: left;
                padding: 8px;
                color: #94a3b8;
                border-bottom: 1px solid var(--border);
            }
            .audit-table td {
                padding: 8px;
                border-bottom: 1px solid rgba(255,255,255,0.04);
            }
            .badge-blocked {
                background: rgba(244, 63, 94, 0.2);
                color: #fb7185;
                border: 1px solid rgba(244, 63, 94, 0.4);
                padding: 2px 6px;
                border-radius: 4px;
                font-weight: 700;
            }
            .badge-allowed {
                background: rgba(16, 185, 129, 0.2);
                color: #34d399;
                border: 1px solid rgba(16, 185, 129, 0.4);
                padding: 2px 6px;
                border-radius: 4px;
                font-weight: 700;
            }
        </style>
    </head>
    <body>
        <!-- HEADER -->
        <header class="header-banner">
            <div class="brand-box">
                <div class="brand-logo">🛒</div>
                <div>
                    <div class="brand-name">QuickPost Market <span style="font-size:12px; color:#cbd5e1; font-weight:500;">(External Website X)</span></div>
                    <div class="brand-tag">Classifieds & Marketplace Demonstration Platform</div>
                </div>
            </div>

            <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                <div class="shield-status-pill">
                    <div class="pulse-dot"></div>
                    <span>🛡️ Protected by FraudShield AI API (Port 8000)</span>
                </div>
                <a href="http://127.0.0.1:8000" target="_blank" style="text-decoration:none; color:#38bdf8; font-size:12px; font-weight:700; background:rgba(56,189,248,0.1); border:1px solid rgba(56,189,248,0.3); padding:6px 12px; border-radius:8px;">
                    🛡️ Open FraudShield Hub ↗
                </a>
            </div>
        </header>

        <main class="container">
            <!-- NOTIFICATION BANNERS -->
            <div id="alertBoxBlocked" class="alert-banner alert-blocked">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="font-weight:800; font-size:14px; color:#fb7185; display:flex; align-items:center; gap:6px;">
                        <span>🛑 SUBMISSION REJECTED: HTTP 403 FORBIDDEN</span>
                    </div>
                    <span id="blockScanId" style="font-family:'JetBrains Mono',monospace; font-size:11px; background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:4px;"></span>
                </div>
                <div style="font-size:13px; font-weight:700; color:#fff; margin-bottom:6px;">
                    Authoritative Directive Received from FraudShield AI Gateway:
                </div>
                <div id="blockDirectiveText" style="font-size:12px; line-height:1.4; color:#fecdd3; background:rgba(0,0,0,0.25); padding:8px 10px; border-radius:6px; border-left:3px solid #f43f5e; margin-bottom:8px;"></div>
                <div style="font-size:11px; color:#cbd5e1;" id="blockReasonsText"></div>
            </div>

            <div id="alertBoxPublished" class="alert-banner alert-published">
                <div style="font-weight:800; font-size:14px; color:#34d399; margin-bottom:4px;">
                    ✅ LISTING VERIFIED & PUBLISHED SUCCESSFULLY!
                </div>
                <div style="font-size:12px; color:#e2e8f0;" id="publishMsgText">
                    Content was inspected and authorized by FraudShield AI pre-publish gate (Clean).
                </div>
            </div>

            <div class="grid-main">
                <!-- LEFT: CREATE NEW LISTING FORM -->
                <div class="panel-card">
                    <div class="panel-title">
                        <span>📝 Create New Post / Marketplace Listing</span>
                    </div>
                    <p class="panel-desc">
                        Every submission is inspected in real-time by calling <code>http://127.0.0.1:8000/api/v1/protect</code> before publication. Malicious cyber threats, phishing links, and fake flyers are blocked immediately.
                    </p>

                    <!-- Attack Scenario Demos -->
                    <div class="preset-bar">
                        <span style="font-size:10px; font-weight:700; color:#94a3b8; text-transform:uppercase;">1-Click Demos:</span>
                        <button type="button" class="btn-preset btn-preset-danger" onclick="fillListingScenario('bank_hack')">
                            🚨 Bank Hack Phishing
                        </button>
                        <button type="button" class="btn-preset btn-preset-danger" onclick="fillListingScenario('electricity_cut')">
                            ⚡ Electricity Notice Threat
                        </button>
                        <button type="button" class="btn-preset btn-preset-danger" onclick="fillListingScenario('lottery_scam')">
                            🎁 Lottery Prize Scam
                        </button>
                        <button type="button" class="btn-preset btn-preset-clean" onclick="fillListingScenario('clean_ad')">
                            ✅ Clean Safe Furniture
                        </button>
                    </div>

                    <form id="listingForm" onsubmit="handleListingSubmit(event)">
                        <div class="form-group">
                            <label class="form-label">Listing Title:</label>
                            <input type="text" id="postTitle" class="form-input" placeholder="e.g. Vintage Study Desk / Urgent Alert" required>
                        </div>

                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;" class="form-group">
                            <div>
                                <label class="form-label">Category:</label>
                                <select id="postCategory" class="form-select">
                                    <option value="Electronics">Electronics & Gadgets</option>
                                    <option value="Furniture">Home & Furniture</option>
                                    <option value="Banking & Finance">Banking & Finance Notice</option>
                                    <option value="Utility Notice">Utility / Electricity</option>
                                    <option value="General">General Classified</option>
                                </select>
                            </div>
                            <div>
                                <label class="form-label">Price (Optional):</label>
                                <input type="text" id="postPrice" class="form-input" placeholder="e.g. Rs. 2,500">
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Description / Post Content:</label>
                            <textarea id="postDesc" class="form-textarea" placeholder="Describe the item or paste post content..." required></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Attached URL / Website Link (Optional):</label>
                            <input type="text" id="postLink" class="form-input" placeholder="e.g. http://sbi-kyc-update.xyz/login.php">
                        </div>

                        <div class="form-group">
                            <label class="form-label">Attached Image / Screenshot / Flyer (Optional):</label>
                            <div style="display:flex; gap:8px; align-items:center;">
                                <input type="file" id="postImageFile" accept="image/*" style="font-size:11px; color:#94a3b8;" onchange="handleImageFileSelect(this.files[0])">
                                <button type="button" class="btn-preset" id="btnClearImg" style="display:none; color:#f43f5e;" onclick="clearUploadedImage()">Remove</button>
                            </div>
                            <div id="imageStatusText" style="font-size:11px; color:var(--blue); margin-top:4px;"></div>
                        </div>

                        <button type="submit" id="btnSubmitListing" class="btn-publish">
                            <span>🚀 Publish Listing to Website X</span>
                        </button>
                    </form>
                </div>

                <!-- RIGHT: LIVE FEED & SECURITY AUDIT -->
                <div>
                    <!-- Security Inspection Monitor Box -->
                    <div class="panel-card" style="margin-bottom:20px; border-color:rgba(56,189,248,0.3);">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                            <div class="panel-title" style="color:var(--blue); margin-bottom:0;">
                                <span>📡 Live FraudShield Security Interception Log</span>
                            </div>
                            <span style="font-size:11px; font-family:'JetBrains Mono',monospace; color:#94a3b8;">
                                Client: Website-X-QuickPostMarket
                            </span>
                        </div>
                        <div style="max-height:160px; overflow-y:auto;">
                            <table class="audit-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Post Title</th>
                                        <th>FraudShield Demand</th>
                                        <th>Risk Score</th>
                                        <th>Latency</th>
                                    </tr>
                                </thead>
                                <tbody id="auditLogTbody">
                                    <tr><td colspan="5" style="text-align:center; color:#64748b;">No recent API requests.</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Marketplace Listings Feed -->
                    <div class="panel-card">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                            <div class="panel-title" style="margin-bottom:0;">
                                <span>🛍️ Published Marketplace Listings</span>
                            </div>
                            <span id="listingsCountBadge" style="font-size:11px; background:rgba(255,255,255,0.06); padding:2px 8px; border-radius:6px; color:#cbd5e1;">
                                2 Verified Posts
                            </span>
                        </div>

                        <div id="listingsFeedContainer" style="max-height:420px; overflow-y:auto; padding-right:4px;">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <script>
            let currentImageBase64 = '';

            function fillListingScenario(type) {
                clearUploadedImage();
                hideAlerts();
                const title = document.getElementById('postTitle');
                const cat = document.getElementById('postCategory');
                const price = document.getElementById('postPrice');
                const desc = document.getElementById('postDesc');
                const link = document.getElementById('postLink');

                if (type === 'bank_hack') {
                    title.value = 'URGENT: Your SBI Bank Account is Blocked';
                    cat.value = 'Banking & Finance';
                    price.value = 'Action Required';
                    desc.value = 'Dear customer, your bank account has been compromised by cyber attackers. Update your KYC PAN immediately to restore access or account will be frozen within 2 hours.';
                    link.value = 'http://sbi-kyc-update.xyz/login.php';
                } else if (type === 'electricity_cut') {
                    title.value = 'Electricity Disconnection Final Notice';
                    cat.value = 'Utility Notice';
                    price.value = 'Rs. 1,420 Due';
                    desc.value = 'Dear consumer, power supply will be terminated tonight at 9:30 PM. Download the payment update utility or contact officer at 9876543210 immediately.';
                    link.value = 'http://electricity-bill-pay.com/update.apk';
                } else if (type === 'lottery_scam') {
                    title.value = 'KBC Lucky Draw 25 Lakh Prize Claim';
                    cat.value = 'General';
                    price.value = 'Prize: Rs 25,00,000';
                    desc.value = 'Congratulations! You have won Rs 25,00,000 in KBC All India Lucky Draw. Send verification fee of Rs 500 via UPI to claim-kbc-reward@ybl to release funds.';
                    link.value = '';
                } else if (type === 'clean_ad') {
                    title.value = 'Vintage Wooden Bookshelf (4 Shelves)';
                    cat.value = 'Furniture';
                    price.value = 'Rs. 2,200';
                    desc.value = 'Solid dark wood bookshelf in great shape. Clean and sturdy, holds 80+ books. Selling because I am downsizing my apartment.';
                    link.value = '';
                }
            }

            function handleImageFileSelect(file) {
                if (!file) return;
                const reader = new FileReader();
                reader.onload = (e) => {
                    currentImageBase64 = e.target.result;
                    document.getElementById('imageStatusText').innerText = `Attached: ${file.name} (${Math.round(file.size/1024)} KB)`;
                    document.getElementById('btnClearImg').style.display = 'inline-block';
                };
                reader.readAsDataURL(file);
            }

            function clearUploadedImage() {
                currentImageBase64 = '';
                const f = document.getElementById('postImageFile');
                if (f) f.value = '';
                document.getElementById('imageStatusText').innerText = '';
                document.getElementById('btnClearImg').style.display = 'none';
            }

            function hideAlerts() {
                document.getElementById('alertBoxBlocked').style.display = 'none';
                document.getElementById('alertBoxPublished').style.display = 'none';
            }

            async function handleListingSubmit(e) {
                e.preventDefault();
                hideAlerts();
                const btn = document.getElementById('btnSubmitListing');
                btn.disabled = true;
                btn.innerHTML = '<span>⏳ Inspecting via FraudShield AI API...</span>';

                const payload = {
                    title: document.getElementById('postTitle').value.trim(),
                    category: document.getElementById('postCategory').value,
                    price: document.getElementById('postPrice').value.trim(),
                    description: document.getElementById('postDesc').value.trim(),
                    link: document.getElementById('postLink').value.trim(),
                    image_base64: currentImageBase64
                };

                try {
                    const res = await fetch('/api/publish', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    const data = await res.json();

                    if (res.status === 403 || !data.success) {
                        // 🛑 BLOCKED BY FRAUDSHIELD AI
                        const bBox = document.getElementById('alertBoxBlocked');
                        bBox.style.display = 'block';
                        document.getElementById('blockScanId').innerText = data.scan_id || 'FS-GATEWAY-BLOCKED';
                        document.getElementById('blockDirectiveText').innerText = data.enforcement_directive || 'DEMAND TO WEBSITE X: BLOCK IMMEDIATELY';
                        
                        let rText = `<b>Threat Assessment:</b> Risk Score: ${data.risk_score} / 100 • Classification: ${data.threat_type || 'Malicious Threat'}<br>`;
                        if (data.reasons && data.reasons.length > 0) {
                            rText += '<ul style="margin:6px 0 0 16px;">' + data.reasons.map(r => `<li>${r}</li>`).join('') + '</ul>';
                        }
                        document.getElementById('blockReasonsText').innerHTML = rText;
                        bBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    } else {
                        // ✅ VERIFIED & PUBLISHED
                        const pBox = document.getElementById('alertBoxPublished');
                        pBox.style.display = 'block';
                        document.getElementById('publishMsgText').innerText = 
                            `Post approved by FraudShield AI (Risk Score: ${data.fraudshield_audit.risk_score} / 100 - Clean in ${data.fraudshield_audit.latency_ms}ms). Added to marketplace feed!`;
                        
                        // Clear inputs
                        document.getElementById('postTitle').value = '';
                        document.getElementById('postDesc').value = '';
                        document.getElementById('postPrice').value = '';
                        document.getElementById('postLink').value = '';
                        clearUploadedImage();

                        // Reload listings
                        fetchListings();
                        pBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }

                    // Refresh security audit logs
                    fetchAuditLogs();

                } catch(err) {
                    alert('Network error connecting to Website X server: ' + err.message);
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = '<span>🚀 Publish Listing to Website X</span>';
                }
            }

            async function fetchListings() {
                try {
                    const res = await fetch('/api/listings');
                    const data = await res.json();
                    const container = document.getElementById('listingsFeedContainer');
                    document.getElementById('listingsCountBadge').innerText = `${data.total} Verified Posts`;

                    if (!data.listings || data.listings.length === 0) {
                        container.innerHTML = '<div style="color:#64748b; font-size:12px; text-align:center; padding:20px;">No listings published yet.</div>';
                        return;
                    }

                    container.innerHTML = data.listings.map(item => `
                        <div class="listing-card">
                            <div class="listing-top">
                                <div>
                                    <div class="listing-title">${escapeHtml(item.title)}</div>
                                    <div class="listing-meta">
                                        <span>📁 ${escapeHtml(item.category)}</span>
                                        <span>•</span>
                                        <span>🕒 ${escapeHtml(item.timestamp)}</span>
                                    </div>
                                </div>
                                <div class="listing-price">${escapeHtml(item.price)}</div>
                            </div>
                            <div style="font-size:12px; color:#cbd5e1; line-height:1.4;">${escapeHtml(item.description)}</div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
                                <div class="shield-verified-badge">
                                    <span>🛡️ Verified Clean by FraudShield AI</span>
                                    <span>(${item.risk_score || 0}/100)</span>
                                </div>
                                <span style="font-size:10px; color:#64748b; font-family:'JetBrains Mono',monospace;">ID: ${item.scan_id || 'FS-OK'}</span>
                            </div>
                        </div>
                    `).join('');
                } catch(e) {
                    console.error('Failed to fetch listings:', e);
                }
            }

            async function fetchAuditLogs() {
                try {
                    const res = await fetch('/api/audit-logs');
                    const data = await res.json();
                    const tbody = document.getElementById('auditLogTbody');
                    if (!data.logs || data.logs.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#64748b;">No recent API requests.</td></tr>';
                        return;
                    }
                    tbody.innerHTML = data.logs.map(log => `
                        <tr>
                            <td style="color:#94a3b8; font-family:'JetBrains Mono',monospace;">${log.timestamp}</td>
                            <td style="max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:600;">${escapeHtml(log.title)}</td>
                            <td>
                                <span class="${log.is_threat ? 'badge-blocked' : 'badge-allowed'}">
                                    ${log.is_threat ? '🛑 BLOCKED' : '🟢 ALLOWED'}
                                </span>
                            </td>
                            <td style="font-weight:700; color:${log.risk_score >= 70 ? '#f43f5e' : '#34d399'};">${log.risk_score}</td>
                            <td style="color:#38bdf8; font-family:'JetBrains Mono',monospace;">${log.latency_ms}ms</td>
                        </tr>
                    `).join('');
                } catch(e) {
                    console.error('Failed to fetch audit logs:', e);
                }
            }

            function escapeHtml(text) {
                if (!text) return '';
                const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
                return text.replace(/[&<>"']/g, m => map[m]);
            }

            window.addEventListener('DOMContentLoaded', () => {
                fetchListings();
                fetchAuditLogs();
            });
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    print("=" * 65)
    print("[ONLINE] QuickPost Market (Website X): http://127.0.0.1:5000")
    print("[CONNECTED] FraudShield AI Gateway: http://127.0.0.1:8000")
    print("=" * 65)
    uvicorn.run("website_x:app", host="127.0.0.1", port=5000, reload=True)
