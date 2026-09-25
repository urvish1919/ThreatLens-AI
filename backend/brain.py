"""
brain.py  (SentinelCore — the correlation engine)

Runs quietly in the background, checking shared_events.db every
CHECK_INTERVAL_SECONDS. It does NOT scan anything itself — it only reads
what ThreatLens and BaitTrace have already found, and looks for the same
IP address appearing from BOTH sources.

If it finds a match it hasn't already alerted on, it sends ONE
"be careful" Telegram message and logs it to the correlated_alerts table
(so it never repeats the same alert twice).

CONNECTING YOUR HONEYPOT (BaitTrace):
BaitTrace is a separate project, so this file can't see its data yet.
You have two options — pick whichever is easier for your setup:

  Option A (simplest): add one line to BaitTrace's existing event-logging
  code, importing log_event from shared_events.py and calling it whenever
  BaitTrace records an attacker session, e.g.:

      from shared_events import log_event
      log_event(
          source="honeypot",
          ip=attacker_ip,
          event_type="brute_force",
          detail=f"{attempt_count} failed SSH logins",
          severity="Malicious"
      )

  Option B: if BaitTrace's backend runs as a separate service and can't
  easily import this file, expose a small endpoint on it (or point this
  brain at its existing database) and pull new rows periodically instead.
  Tell me which BaitTrace uses (its own SQLite table name/columns) and
  I'll write the exact bridge code for that.

Until BaitTrace is connected, this file will simply find no honeypot
events to match against — ThreatLens alerts (Layer 1) still work fine
on their own in the meantime.
"""

import time
from shared_events import get_recent_events, connection, cursor
from telegram_alert import send_alert

CHECK_INTERVAL_SECONDS = 60
MATCH_WINDOW_MINUTES = 1440  # look for matches within the last 24 hours


def already_alerted(ip, honeypot_event_id, threatlens_event_id):
    cursor.execute(
        """
        SELECT id FROM correlated_alerts
        WHERE ip = ? AND honeypot_event_id = ? AND threatlens_event_id = ?
        """,
        (ip, honeypot_event_id, threatlens_event_id)
    )
    return cursor.fetchone() is not None


def save_alert(ip, honeypot_event, threatlens_event, summary):
    cursor.execute(
        """
        INSERT INTO correlated_alerts (ip, honeypot_event_id, threatlens_event_id, summary)
        VALUES (?, ?, ?, ?)
        """,
        (ip, honeypot_event["id"], threatlens_event["id"], summary)
    )
    connection.commit()


def check_for_correlations():
    honeypot_events = get_recent_events(source="honeypot", since_minutes=MATCH_WINDOW_MINUTES)
    threatlens_events = get_recent_events(source="threatlens", since_minutes=MATCH_WINDOW_MINUTES)

    # Only bother matching on real IPs, and only care about risky ThreatLens events —
    # a Safe email from the same IP as a honeypot hit isn't worth flagging.
    risky_threatlens = [e for e in threatlens_events if e["severity"] in ("Suspicious", "Malicious")]

    for hp_event in honeypot_events:
        if hp_event["ip"] in ("unknown", "", None):
            continue

        for tl_event in risky_threatlens:
            if tl_event["ip"] == hp_event["ip"]:

                if already_alerted(hp_event["ip"], hp_event["id"], tl_event["id"]):
                    continue

                summary = (
                    f"⚠️ CORRELATED ATTACK — be careful\n\n"
                    f"IP: {hp_event['ip']}\n\n"
                    f"🐝 Honeypot: {hp_event['detail']} ({hp_event['created_at']})\n"
                    f"📧 Email: {tl_event['detail']} ({tl_event['created_at']})\n\n"
                    f"Same IP hit your honeypot AND sent you a risky email/link.\n"
                    f"This looks like a real, targeted attempt — not random spam."
                )

                print("[brain] Correlation found:", summary)
                send_alert(summary)
                save_alert(hp_event["ip"], hp_event, tl_event, summary)


def run():
    print("[brain] SentinelCore running. Watching for correlated attacks...")
    while True:
        try:
            check_for_correlations()
        except Exception as e:
            print("[brain] Error:", e)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()