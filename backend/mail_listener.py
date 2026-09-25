"""
mail_listener.py

Watches the RECEIVER dummy Gmail inbox every POLL_INTERVAL_SECONDS,
using simple IMAP + App Password login (no Google Cloud Console,
no OAuth, no credentials.json needed).

For every new email:
  1. Pulls the sender's IP from the 'Authentication-Results' header (SPF)
  2. Downloads any attachments -> scans with your existing analyze_file()
  3. Extracts any URLs from the email body -> scans with analyze_url()
  4. Logs every result into shared_events.db (so the Brain can correlate later)
  5. If Suspicious/Malicious -> sends a Telegram alert IMMEDIATELY (Layer 1)
  6. Labels the email in Gmail: "ThreatLens-Risky" or "ThreatLens-Safe"
     (using Gmail's IMAP label extension, no separate API call needed)

SETUP NEEDED BEFORE RUNNING (one-time, no Google Cloud Console):
1. Log into the RECEIVER dummy Gmail account
2. Turn on 2-Step Verification (Security settings) - free, just needs a phone number
3. Go to myaccount.google.com/apppasswords -> create one named "ThreatLens"
4. Copy the 16-character App Password it gives you
5. In your .env, set:
     RECEIVER_EMAIL=your.receiver.dummy@gmail.com
     RECEIVER_APP_PASSWORD=the16characterpassword
6. pip install -r requirements.txt (no new packages needed - imaplib/email
   are built into Python already)
7. Run: python mail_listener.py
"""

import os
import re
import time
import email
from email.header import decode_header

import imaplib

from dotenv import load_dotenv

from scanner import analyze_file, analyze_url
from shared_events import log_event
from telegram_alert import send_alert

load_dotenv()

# ---------------------------------------------------------
# Config
# ---------------------------------------------------------

IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.getenv("RECEIVER_EMAIL")
APP_PASSWORD = os.getenv("RECEIVER_APP_PASSWORD")

POLL_INTERVAL_SECONDS = 90       # check inbox every 90 seconds
VT_DELAY_SECONDS = 16            # ~4 requests/minute on VirusTotal free tier -> ~15s gap between scans

UPLOAD_FOLDER = "mail_attachments"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

RISKY_STATUSES = {"Suspicious", "Malicious"}


# ---------------------------------------------------------
# IMAP connection
# ---------------------------------------------------------

def connect():
    if not EMAIL_ACCOUNT or not APP_PASSWORD:
        raise RuntimeError(
            "Missing RECEIVER_EMAIL or RECEIVER_APP_PASSWORD in .env. "
            "See the setup steps at the top of this file."
        )
    imap = imaplib.IMAP4_SSL(IMAP_SERVER)
    imap.login(EMAIL_ACCOUNT, APP_PASSWORD)
    return imap


# ---------------------------------------------------------
# Helpers: extract sender IP, attachments, URLs
# ---------------------------------------------------------

def extract_sender_ip(msg):
    """
    Pulls the IP out of the 'Authentication-Results' header, e.g.:
    'spf=pass (google.com: domain of ... client-ip=103.52.180.165) ...'
    Falls back to scanning 'Received' headers if that's missing.
    """
    auth_results = msg.get("Authentication-Results", "") or ""
    match = re.search(r"client-ip=([\d.]+)", auth_results)
    if match:
        return match.group(1)

    for value in msg.get_all("Received", []):
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", value)
        if ip_match:
            return ip_match.group(1)

    return "unknown"


def extract_urls(text):
    return list(set(re.findall(r"https?://[^\s<>\"']+", text or "")))


def get_body_text(msg):
    """Walks the email to pull out plain text body, skipping attachments."""
    if msg.is_multipart():
        text = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                try:
                    text += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass
        return text
    else:
        try:
            return msg.get_payload(decode=True).decode(errors="ignore")
        except Exception:
            return ""


def save_attachments(msg, uid_str):
    """Saves every attachment to disk, returns list of (filename, filepath)."""
    saved = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            decoded = decode_header(filename)[0][0]
            if isinstance(decoded, bytes):
                filename = decoded.decode(errors="ignore")
            filepath = os.path.join(UPLOAD_FOLDER, f"{uid_str}_{filename}")
            payload = part.get_payload(decode=True)
            if payload:
                with open(filepath, "wb") as f:
                    f.write(payload)
                saved.append((filename, filepath))
    return saved


def apply_label(imap, uid, label):
    """
    Uses Gmail's IMAP extension (X-GM-LABELS) to add a label WITHOUT
    moving or deleting the email - fully safe and reversible.
    """
    imap.uid('STORE', uid, '+X-GM-LABELS', f'({label})')


# ---------------------------------------------------------
# Main processing for one email
# ---------------------------------------------------------

def process_message(imap, uid):
    status, msg_data = imap.uid('fetch', uid, '(RFC822)')
    if not msg_data or not msg_data[0]:
        return

    raw_email = msg_data[0][1]
    msg = email.message_from_bytes(raw_email)

    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    sender_ip = extract_sender_ip(msg)
    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)

    print(f"\n[mail_listener] New email from {sender} | subject: {subject} | sender IP: {sender_ip}")

    findings = []

    # ---- Scan attachments ----
    attachments = save_attachments(msg, uid_str)
    for filename, filepath in attachments:
        print(f"[mail_listener] Scanning attachment: {filename}")
        result = analyze_file(filepath)
        findings.append(("file", filename, result["status"], result["threat_score"]))

        log_event(
            source="threatlens",
            ip=sender_ip,
            event_type="malicious_file" if result["status"] != "Safe" else "file_scan",
            detail=f"Attachment '{filename}' from {sender} -> {result['status']} (score {result['threat_score']})",
            severity=result["status"],
        )

        if result["status"] in RISKY_STATUSES:
            send_alert(
                f"🚨 ThreatLens Alert\n"
                f"Risky attachment: {filename}\n"
                f"From: {sender}\n"
                f"Sender IP: {sender_ip}\n"
                f"Status: {result['status']} (score {result['threat_score']}/100)\n"
                f"Subject: {subject}"
            )

        time.sleep(VT_DELAY_SECONDS)

    # ---- Scan URLs in body ----
    body_text = get_body_text(msg)
    urls = extract_urls(body_text)
    for url in urls:
        print(f"[mail_listener] Scanning URL: {url}")
        result = analyze_url(url)
        findings.append(("url", url, result["status"], result["threat_score"]))

        log_event(
            source="threatlens",
            ip=sender_ip,
            event_type="malicious_url" if result["status"] != "Safe" else "url_scan",
            detail=f"URL '{url}' from {sender} -> {result['status']} (score {result['threat_score']})",
            severity=result["status"],
        )

        if result["status"] in RISKY_STATUSES:
            send_alert(
                f"🚨 ThreatLens Alert\n"
                f"Risky link in email: {url}\n"
                f"From: {sender}\n"
                f"Sender IP: {sender_ip}\n"
                f"Status: {result['status']} (score {result['threat_score']}/100)\n"
                f"Subject: {subject}"
            )

        time.sleep(VT_DELAY_SECONDS)

    # ---- If email had nothing to scan, still log it as a baseline event ----
    if not findings:
        log_event(
            source="threatlens",
            ip=sender_ip,
            event_type="plain_email",
            detail=f"Email from {sender} with no attachments/links",
            severity="Safe",
        )

    # ---- Label the email ----
    overall_risky = any(status in RISKY_STATUSES for _, _, status, _ in findings)
    try:
        apply_label(imap, uid, "ThreatLens-Risky" if overall_risky else "ThreatLens-Safe")
    except Exception as e:
        print("[mail_listener] Labeling failed (non-fatal):", e)


# ---------------------------------------------------------
# Polling loop
# ---------------------------------------------------------

def run():
    print("[mail_listener] Connecting via IMAP...")
    imap = connect()
    imap.select("INBOX")
    print("[mail_listener] Connected. Watching inbox for new mail...")

    # Baseline: mark all existing mail as already-seen so we don't
    # re-scan your whole inbox history on first run.
    status, data = imap.uid('search', None, 'ALL')
    seen_uids = set(data[0].split()) if data and data[0] else set()
    print(f"[mail_listener] Baseline set: ignoring {len(seen_uids)} existing emails.")

    while True:
        try:
            # Re-select INBOX every loop - this forces Gmail's IMAP server to
            # refresh its view of the mailbox. Without this, some IMAP sessions
            # can go "stale" and keep reporting the same old message list even
            # when new mail has actually arrived.
            imap.select("INBOX")

            status, data = imap.uid('search', None, 'ALL')
            current_uids = data[0].split() if data and data[0] else []

            new_ones = [uid for uid in current_uids if uid not in seen_uids]
            print(f"[mail_listener] Checked inbox — {len(current_uids)} total, {len(new_ones)} new.")

            for uid in new_ones:
                seen_uids.add(uid)
                process_message(imap, uid)

        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError) as e:
            print("[mail_listener] Connection issue, reconnecting:", e)
            try:
                imap.logout()
            except Exception:
                pass
            time.sleep(5)
            imap = connect()
            imap.select("INBOX")

        except Exception as e:
            print("[mail_listener] Error during poll:", e)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()