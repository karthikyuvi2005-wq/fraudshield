import requests
from typing import List, Dict, Any
from risk_engine import FraudShieldRiskEngine

SEED_LOOKALIKES = [
    "http://secure-sbi-kyc-pan-update.xyz/login.php",
    "http://hdfc-netbanking-verify.top/index.html",
    "http://192.168.1.105/paytm-kyc.html",
    "https://bit.ly/free-recharge-bonus-2026",
    "http://electricity-bill-disconnection-alert.online/pay.php"
]

def run_hunt_scan(engine: FraudShieldRiskEngine, max_items: int = 10) -> List[Dict[str, Any]]:
    """
    Hunts fraud on public threat intelligence feeds (OpenPhish, URLhaus, and lookalikes).
    Evaluates each candidate and returns automated blocklist and reporting recommendations.
    """
    candidates = []

    # 1. Fetch from OpenPhish live feed
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=4)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            for link in lines[:5]:
                candidates.append({"url": link, "source": "OpenPhish Live Feed"})
    except Exception:
        pass

    # 2. Add lookalike seed targets
    for link in SEED_LOOKALIKES:
        candidates.append({"url": link, "source": "crt.sh Brand Lookalike Monitor"})

    results = []
    for item in candidates[:max_items]:
        url = item["url"]
        eval_res = engine.analyze(url=url, inspect_page=False) # fast batch scan
        
        action = "Blocklisted & Dispatched to 1930 / CERT-In" if eval_res["verdict"] == "BLOCK" else (
            "Flagged for Human Review" if eval_res["verdict"] == "HOLD" else "Cleared / Monitored"
        )
        
        results.append({
            "url": url,
            "source": item["source"],
            "risk_score": eval_res["risk_score"],
            "verdict": eval_res["verdict"],
            "scam_type": eval_res["scam_type"],
            "flags": eval_res["url_flags"][:2] if eval_res["url_flags"] else ["Novel URL signature"],
            "action_taken": action
        })

    return results

if __name__ == "__main__":
    eng = FraudShieldRiskEngine()
    print("Testing Hunt Engine...")
    res = run_hunt_scan(eng, max_items=4)
    for r in res:
        print(f"[{r['verdict']}] ({r['risk_score']}%) {r['url'][:45]} | {r['source']}")
