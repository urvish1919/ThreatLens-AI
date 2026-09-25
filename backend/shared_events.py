"""
shared_events.py

ONE shared table that BOTH ThreatLens (email scanner) and BaitTrace (honeypot)
write their findings into. This is the "shared diary" the Brain reads from
to look for matching IP addresses.

ThreatLens writes rows here automatically (see mail_listener.py).
For BaitTrace, you just need to add a few lines in its existing code that
call log_event(source="honeypot", ...) whenever it logs an attacker session.
You don't need to touch BaitTrace's own dashboard/DB — this is separate,
just for correlation.
"""

import sqlite3
from datetime import datetime

DB_PATH = "shared_events.db"

connection = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,          -- 'honeypot' or 'threatlens'
    ip TEXT,               -- the IP address involved
    event_type TEXT,       -- e.g. 'brute_force', 'malicious_file', 'malicious_url'
    detail TEXT,            -- human-readable description
    severity TEXT,          -- 'Safe' / 'Suspicious' / 'Malicious'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS correlated_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    honeypot_event_id INTEGER,
    threatlens_event_id INTEGER,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

connection.commit()


def log_event(source, ip, event_type, detail, severity):
    """
    Call this any time either tool finds something worth recording.
    Example:
        log_event(
            source="threatlens",
            ip="185.220.101.45",
            event_type="malicious_file",
            detail="invoice.exe flagged MALICIOUS by VirusTotal (32 engines)",
            severity="Malicious"
        )
    """
    cursor.execute(
        """
        INSERT INTO events (source, ip, event_type, detail, severity)
        VALUES (?, ?, ?, ?, ?)
        """,
        (source, ip, event_type, detail, severity)
    )
    connection.commit()
    return cursor.lastrowid


def get_recent_events(source=None, since_minutes=1440):
    """
    Fetch recent events, optionally filtered by source.
    Default window: last 24 hours (1440 minutes) — honeypot hits and
    a follow-up email don't always land minutes apart, so we look back
    a full day rather than just a few minutes.
    """
    query = """
        SELECT id, source, ip, event_type, detail, severity, created_at
        FROM events
        WHERE created_at >= datetime('now', ?)
    """
    params = [f"-{since_minutes} minutes"]

    if source:
        query += " AND source = ?"
        params.append(source)

    query += " ORDER BY created_at DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()

    return [
        {
            "id": r[0], "source": r[1], "ip": r[2], "event_type": r[3],
            "detail": r[4], "severity": r[5], "created_at": r[6]
        }
        for r in rows
    ]