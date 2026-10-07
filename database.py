import sqlite3
import datetime
from typing import List, Dict, Any, Optional

DB_FILE = "fraudshield.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 1. Incidents Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            text_preview TEXT,
            url TEXT,
            risk_score REAL NOT NULL,
            risk_tier TEXT NOT NULL,
            verdict TEXT NOT NULL,
            scam_type TEXT NOT NULL
        )
    """)

    # 2. Users Table
    cursor.execute("PRAGMA table_info(users)")
    cols = [col[1] for col in cursor.fetchall()]
    if cols and "organization" not in cols:
        cursor.execute("DROP TABLE users")
        cols = []

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            organization TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    # Seed default student demo user if not present
    cursor.execute("SELECT id FROM users WHERE email = 'karthik@hackscribe.dev'")
    if not cursor.fetchone():
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO users (name, email, phone, organization, password, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "Karthik V.",
            "karthik@hackscribe.dev",
            "+91 98765 43210",
            "Team Hackscribe (CSE)",
            "password123",
            ts
        ))
        conn.commit()

    conn.close()

def register_user(name: str, email: str, phone: str, organization: str, password: str) -> Dict[str, Any]:
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cursor.execute("""
            INSERT INTO users (name, email, phone, organization, password, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name.strip(), email.lower().strip(), phone.strip(), organization.strip(), password, ts))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {
            "success": True,
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "phone": phone,
                "organization": organization
            }
        }
    except sqlite3.IntegrityError:
        conn.close()
        return {"success": False, "error": "An account with this email address already exists. Please sign in."}
    except Exception as e:
        conn.close()
        return {"success": False, "error": str(e)}

def authenticate_user(identifier: str, password: str) -> Optional[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    ident = identifier.strip().lower()
    
    cursor.execute("""
        SELECT id, name, email, phone, organization, password
        FROM users
        WHERE (LOWER(email) = ? OR phone = ?) AND password = ?
    """, (ident, identifier.strip(), password))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "phone": row[3],
            "organization": row[4]
        }
    return None

def log_incident(text: str, url: str, risk_score: float, risk_tier: str, verdict: str, scam_type: str):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    preview = (text[:80] + "...") if len(text) > 80 else text
    cursor.execute("""
        INSERT INTO incidents (timestamp, text_preview, url, risk_score, risk_tier, verdict, scam_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ts, preview, url or "N/A", risk_score, risk_tier, verdict, scam_type))
    conn.commit()
    conn.close()

def get_recent_incidents(limit: int = 25) -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, text_preview, url, risk_score, risk_tier, verdict, scam_type
        FROM incidents ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "text": r[2],
            "url": r[3],
            "risk_score": r[4],
            "risk_tier": r[5],
            "verdict": r[6],
            "scam_type": r[7]
        }
        for r in rows
    ]

def get_stats() -> Dict[str, Any]:
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM incidents")
    row = cursor.fetchone()
    total = row[0] or 0
    avg_score = round(row[1] or 0.0, 1)

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE verdict = 'BLOCK'")
    blocked = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE verdict = 'HOLD'")
    held = cursor.fetchone()[0] or 0

    conn.close()
    return {
        "total_scans": total,
        "blocked_threats": blocked,
        "held_investigations": held,
        "avg_risk": avg_score
    }

if __name__ == "__main__":
    init_db()
    print("Database updated for student project auth!")
    u = authenticate_user("karthik@hackscribe.dev", "password123")
    print("Demo student login test:", u)
