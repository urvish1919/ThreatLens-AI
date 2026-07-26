import base64
import hashlib
import mimetypes
import os
import re
import time
import requests
import yara

from PyPDF2 import PdfReader

from config import (
    HEADERS,
    VT_FILE_UPLOAD,
    VT_FILE_INFO,
    VT_ANALYSIS,
    VT_URL_SCAN,
    VT_URL_INFO
)

# ==========================
# Load all YARA rules
# ==========================

RULES = yara.compile(
    filepaths={
        "malware": "rules/malware.yar",
        "ransomware": "rules/ransomware.yar",
        "phishing": "rules/phishing.yar",
    }
)


# ==========================
# PDF Scanner Helper
# ==========================

def analyze_pdf(filepath):
    findings = []
    score = 0

    try:
        reader = PdfReader(filepath)
        text = ""

        for page in reader.pages:
            try:
                page_text = page.extract_text()
                if page_text:
                    text += page_text.lower()
            except Exception:
                pass

        suspicious_keywords = [
            "login",
            "verify",
            "password",
            "bank",
            "otp",
            "credit card",
            "bitcoin",
            "wallet",
            "paypal",
            "gift",
        ]

        for word in suspicious_keywords:
            if word in text:
                findings.append(f'Suspicious keyword: "{word}"')
                score += 5

        urls = re.findall(r"https?://[^\s]+", text)
        if urls:
            findings.append(f"{len(urls)} URL(s) found inside PDF")
            score += 10

        root = reader.trailer["/Root"]
        if "/OpenAction" in root:
            findings.append("PDF contains OpenAction")
            score += 25

    except Exception as e:
        print("PDF Analysis Error:", e)

    return score, findings


# ==========================
# File Scanner Function
# ==========================

def analyze_file(filepath):
    filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        file_data = f.read()

    sha256 = hashlib.sha256(file_data).hexdigest()
    file_size_kb = round(len(file_data) / 1024, 2)
    file_type = mimetypes.guess_type(filepath)[0] or "Unknown"

    # -----------------------
    # Local YARA Scan
    # -----------------------
    yara_results = RULES.match(filepath)
    yara_matches = [match.rule for match in yara_results]
    yara_score = len(yara_matches) * 20

    # -----------------------
    # Deep PDF Analysis
    # -----------------------
    pdf_score = 0
    pdf_findings = []

    if filepath.lower().endswith(".pdf"):
        pdf_score, pdf_findings = analyze_pdf(filepath)

    # -----------------------
    # VirusTotal File Analysis
    # -----------------------
    malicious = 0
    suspicious = 0
    harmless = 0
    undetected = 0
    vendors = []

    try:
        response = requests.get(
            f"{VT_FILE_INFO}/{sha256}",
            headers=HEADERS
        )

        # File already exists in VirusTotal database
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            analysis_results = data["data"]["attributes"].get("last_analysis_results", {})
            for engine, result in analysis_results.items():
                if result.get("category") == "malicious":
                    vendors.append({
                        "engine": engine,
                        "result": result.get("result")
                    })

        else:
            with open(filepath, "rb") as f:
                upload = requests.post(
                    VT_FILE_UPLOAD,
                    headers=HEADERS,
                    files={"file": f}
                )

            if upload.status_code in [200, 202]:
                analysis_id = upload.json()["data"]["id"]

                for _ in range(10):
                    time.sleep(3)

                    analysis = requests.get(
                        f"{VT_ANALYSIS}/{analysis_id}",
                        headers=HEADERS
                    )

                    if analysis.status_code != 200:
                        continue

                    analysis_json = analysis.json()

                    if analysis_json["data"]["attributes"]["status"] != "completed":
                        continue

                    file_hash = analysis_json["meta"]["file_info"]["sha256"]

                    report = requests.get(
                        f"{VT_FILE_INFO}/{file_hash}",
                        headers=HEADERS
                    )

                    if report.status_code != 200:
                        break

                    report_json = report.json()
                    stats = report_json["data"]["attributes"]["last_analysis_stats"]

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    analysis_results = report_json["data"]["attributes"].get(
                        "last_analysis_results", {}
                    )

                    for engine, result in analysis_results.items():
                        if result.get("category") == "malicious":
                            vendors.append({
                                "engine": engine,
                                "result": result.get("result")
                            })

                    break

    except Exception as e:
        print("VirusTotal File Analysis Error:", e)

    vt_score = (malicious * 15) + (suspicious * 8)
    threat_score = min(100, yara_score + vt_score + pdf_score)

    if threat_score < 30:
        status = "Safe"
    elif threat_score < 70:
        status = "Suspicious"
    else:
        status = "Malicious"

    return {
        "filename": filename,
        "sha256": sha256,
        "file_size_kb": file_size_kb,
        "file_type": file_type,
        "yara_matches": yara_matches,
        "pdf_findings": pdf_findings,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "vendors": vendors,
        "threat_score": threat_score,
        "status": status,
    }


# ==========================
# URL Scanner Function
# ==========================

def analyze_url(url):
    malicious = 0
    suspicious = 0
    harmless = 0
    undetected = 0
    vendors = []
    reasons = []

    try:

        print("HEADERS =", HEADERS)
        print('VT_URL_SCAN =', VT_URL_SCAN)
        
        # Submit the URL for scanning
        submit = requests.post(
            VT_URL_SCAN,
            headers=HEADERS,
            data={"url": url}
        )

        print("Status Code:", submit.status_code)
        print("Response:", submit.text)

        if submit.status_code not in [200, 202]:
            return {
                "url": url,
                "threat_score": 0,
                "status": "Unknown",
                "reasons": ["VirusTotal URL submission failed."],
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "vendors": [],
            }

        # Encode URL using base64 without trailing '=' padding per VT v3 API spec
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        report = requests.get(
            f"{VT_URL_INFO}/{url_id}",
            headers=HEADERS
        )

        if report.status_code != 200:
            return {
                "url": url,
                "threat_score": 0,
                "status": "Unknown",
                "reasons": ["VirusTotal report unavailable."],
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "vendors": [],
            }

        data = report.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        analysis = data["data"]["attributes"].get("last_analysis_results", {})

        for engine, result in analysis.items():
            if result.get("category") == "malicious":
                vendors.append({
                    "engine": engine,
                    "result": result.get("result")
                })

        threat_score = min(100, (malicious * 15) + (suspicious * 8))

        if threat_score < 30:
            status = "Safe"
        elif threat_score < 70:
            status = "Suspicious"
        else:
            status = "Malicious"

        return {
            "url": url,
            "threat_score": threat_score,
            "status": status,
            "reasons": reasons,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "vendors": vendors,
        }

    except Exception as e:
        return {
            "url": url,
            "threat_score": 0,
            "status": "Unknown",
            "reasons": [str(e)],
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "vendors": [],
        }