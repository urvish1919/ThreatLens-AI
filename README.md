# ThreatLens AI

An AI-assisted cybersecurity threat detection system that scans **files** and **URLs** for potential threats, combining local **YARA rule matching** with **VirusTotal** threat intelligence, and presents results through a **React dashboard**.

Built as a personal project to explore how AI/automation-assisted tooling can support cybersecurity threat detection workflows.

---

## Features

- **File Scanner** — Upload a file to check it for threats:
  - Computes SHA-256 hash
  - Matches file contents against local YARA rules (malware, ransomware, phishing signatures)
  - Cross-checks the file hash against [VirusTotal](https://www.virustotal.com/)'s database of 70+ antivirus engines
  - Combines both signals into a single threat score (0–100) and a status: `Safe`, `Suspicious`, or `Malicious`

- **URL Scanner** — Paste a URL to check it for suspicious characteristics:
  - Flags non-HTTPS links, unusually long URLs, and known phishing-related keywords
  - Returns a threat score and status with reasons for the score

- **Scan History** — All scans (file and URL) are logged to a local database and viewable in the app

- **Dashboard** — At-a-glance stats: total file scans, total URL scans, and breakdown by Safe / Suspicious / Malicious

---

## Tech Stack

**Backend**
- [FastAPI](https://fastapi.tiangolo.com/) (Python)
- [YARA-Python](https://yara.readthedocs.io/) for local signature-based malware detection
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview) for file reputation lookups
- SQLite for scan history storage

**Frontend**
- React
- Recharts (dashboard visualizations)
- Axios / Fetch for API calls

---

## Project Structure

```
ThreatLens-AI/
├── backend/
│   ├── main.py           # FastAPI app & API routes
│   ├── scanner.py         # File scanning logic (YARA + VirusTotal)
│   ├── config.py          # VirusTotal API configuration
│   ├── database.py        # SQLite setup
│   ├── utils.py
│   ├── rules/              # YARA rule files
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── pages/          # Dashboard, FileScanner, URLScanner, History
    │   └── styles/
    └── package.json
```

---

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js & npm
- A free [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)

### Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file inside `backend/`:

```
VT_API_KEY=your_virustotal_api_key_here
```

Run the backend:

```bash
uvicorn main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

The app will open at `http://localhost:3000`.

---

## API Endpoints

| Method | Endpoint      | Description                                  |
|--------|---------------|-----------------------------------------------|
| GET    | `/`           | Health check                                  |
| POST   | `/scan-file`  | Upload a file to scan for threats             |
| POST   | `/scan-url`   | Submit a URL (`{ "url": "..." }`) to scan     |
| GET    | `/history`    | Retrieve all past scans                       |
| GET    | `/dashboard`  | Retrieve aggregate scan statistics            |

---

## Roadmap

This project is under active development. Planned improvements include:

- [ ] Integrating additional real-time threat intelligence sources (Google Safe Browsing, URLhaus/PhishTank) for more accurate URL detection
- [ ] Expanding and refining YARA rule coverage
- [ ] Displaying per-engine VirusTotal detection results in the UI
- [ ] Deploying the app so it's accessible outside localhost

---

## Disclaimer

This is an educational/personal project and is **not** intended for production security use. Always use established, professionally maintained security tools for real threat detection needs.

---

## Author

Built by [Urvish Guthula](https://github.com/urvish1919)
