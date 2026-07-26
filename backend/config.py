import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

# ==========================
# VirusTotal File API
# ==========================

VT_FILE_UPLOAD = "https://www.virustotal.com/api/v3/files"
VT_FILE_INFO = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"

# ==========================
# VirusTotal URL API
# ==========================

VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_INFO = "https://www.virustotal.com/api/v3/urls"