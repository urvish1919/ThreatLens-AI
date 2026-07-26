from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os

from scanner import analyze_file, analyze_url
from database import cursor, connection

app = FastAPI(
    title="ThreatLens AI",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.get("/")
def home():
    return {
        "message": "ThreatLens AI Backend Running Successfully"
    }


# ===========================
# FILE SCANNER
# ===========================

@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = analyze_file(filepath)

    cursor.execute(
        """
        INSERT INTO scan_history
        (scan_type, target, threat_score, status)
        VALUES (?, ?, ?, ?)
        """,
        (
            "File",
            result["filename"],
            result["threat_score"],
            result["status"]
        )
    )

    connection.commit()

    return result


# ===========================
# URL SCANNER
# ===========================

@app.post("/scan-url")
async def scan_url(data: dict):

    url = data.get("url", "").strip()

    result = analyze_url(url)

    cursor.execute(
        """
        INSERT INTO scan_history
        (scan_type, target, threat_score, status)
        VALUES (?, ?, ?, ?)
        """,
        (
            "URL",
            url,
            result["threat_score"],
            result["status"]
        )
    )

    connection.commit()

    return result


# ===========================
# HISTORY
# ===========================

@app.get("/history")
def history():

    cursor.execute("""
        SELECT
            id,
            scan_type,
            target,
            threat_score,
            status,
            scanned_at
        FROM scan_history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    return [
        {
            "id": row[0],
            "scan_type": row[1],
            "target": row[2],
            "threat_score": row[3],
            "status": row[4],
            "scanned_at": row[5]
        }
        for row in rows
    ]


# ===========================
# DASHBOARD
# ===========================

@app.get("/dashboard")
def dashboard():

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='File'")
    file_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE scan_type='URL'")
    url_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Suspicious'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Malicious'")
    malicious = cursor.fetchone()[0]

    return {
        "file_scans": file_scans,
        "url_scans": url_scans,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious
    }