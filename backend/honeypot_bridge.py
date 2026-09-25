"""
honeypot_bridge.py (v2 - HTTP version)

Since BaitTrace is hosted somewhere without terminal/SSH access, this
version polls a new endpoint on BaitTrace's own backend
(/api/raw-events) over the internet, instead of reading cowrie.json
as a local file.

Runs alongside ThreatLens's mail_listener.py and brain.py - can run on
your laptop, or wherever you eventually deploy ThreatLens. It just needs
internet access to reach BaitTrace's public URL.

SETUP NEEDED:
1. Make sure BaitTrace's backend/main.py has the new /api/raw-events
   endpoint (given alongside this file) and is redeployed.
2. In your .env, set:
     BAITTRACE_API_URL=https://your-baittrace-backend-url.com
   (the same base URL your frontend's VITE_API_URL points to)
3. pip install requests (you likely already have this from scanner.py)
4. Run: python honeypot_bridge.py
"""

import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

from shared_events import log_event

load_dotenv()

BAITTRACE_API_URL = os.getenv("BAITTRACE_API_URL", "").rstrip("/")
CHECK_INTERVAL_SECONDS = 15  # polling a URL is fine at this rate, it's just your own API

# Remembers the timestamp of the last event we've already processed,
# saved to a small local file so restarting this script doesn't
# re-process old events from scratch.
STATE_FILE = Path("bridge_state.txt")

RISKY_EVENT_TYPES = {
    "cowrie.login.failed": ("brute_force", "Medium"),
    "cowrie.login.success": ("successful_breach", "Malicious"),
    "cowrie.command.input": ("command_executed", "Suspicious"),
}

CRITICAL_COMMANDS = ["rm -rf", "mkfs", "dd if=", "wget", "curl", "chmod +x", "nc ", "bash -i"]


def load_last_seen():
    if STATE_FILE.exists():
        return STATE_FILE.read_text().strip()
    return ""


def save_last_seen(timestamp):
    STATE_FILE.write_text(timestamp)


def classify_event(event):
    event_id = event.get("eventid", "")

    if event_id not in RISKY_EVENT_TYPES:
        return None

    event_type, severity = RISKY_EVENT_TYPES[event_id]

    if event_id == "cowrie.command.input":
        command = (event.get("input") or "").lower()
        if any(bad in command for bad in CRITICAL_COMMANDS):
            severity = "Malicious"
            event_type = "dangerous_command"

    return event_type, severity


def build_detail(event, event_type):
    ip = event.get("src_ip", "unknown")

    if event_type == "brute_force":
        return f"Failed SSH login attempt from {ip} (user: {event.get('username', '?')})"
    elif event_type == "successful_breach":
        return f"SUCCESSFUL SSH login from {ip} (user: {event.get('username', '?')}) — honeypot was 'breached'"
    elif event_type in ("command_executed", "dangerous_command"):
        return f"Command run by {ip}: {event.get('input', '')}"
    return f"Event from {ip}: {event.get('eventid')}"


def fetch_new_events(since):
    url = f"{BAITTRACE_API_URL}/api/raw-events"
    params = {"since": since} if since else {}

    response = requests.get(url, params=params, timeout=15)
    response.raise_for_status()
    return response.json()


def run():
    if not BAITTRACE_API_URL:
        raise RuntimeError("Missing BAITTRACE_API_URL in .env - set it to BaitTrace's backend URL.")

    print(f"[honeypot_bridge] Watching {BAITTRACE_API_URL}/api/raw-events")

    last_seen = load_last_seen()
    if last_seen:
        print(f"[honeypot_bridge] Resuming from last saved timestamp: {last_seen}")
    else:
        print("[honeypot_bridge] No saved state - fetching baseline (marking existing events as already seen)...")
        try:
            baseline_events = fetch_new_events(since="")
            if baseline_events:
                last_seen = baseline_events[-1].get("timestamp", "")
                save_last_seen(last_seen)
            print(f"[honeypot_bridge] Baseline set: ignoring {len(baseline_events)} existing events.")
        except Exception as e:
            print("[honeypot_bridge] Could not fetch baseline:", e)

    while True:
        try:
            new_events = fetch_new_events(since=last_seen)
            print(f"[honeypot_bridge] Checked BaitTrace — {len(new_events)} new events.")

            for event in new_events:
                classification = classify_event(event)
                timestamp = event.get("timestamp", "")

                if timestamp and timestamp > last_seen:
                    last_seen = timestamp

                if not classification:
                    continue

                event_type, severity = classification
                ip = event.get("src_ip", "unknown")
                detail = build_detail(event, event_type)

                log_event(
                    source="honeypot",
                    ip=ip,
                    event_type=event_type,
                    detail=detail,
                    severity=severity,
                )
                print(f"[honeypot_bridge] Logged real event: {detail}")

            if last_seen:
                save_last_seen(last_seen)

        except Exception as e:
            print("[honeypot_bridge] Error:", e)

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()