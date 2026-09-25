"""
test_insert.py

ONE-TIME TEST SCRIPT - not part of the real system.

This simulates a honeypot event using the SAME IP that already showed up
in your ThreatLens test (209.85.220.41), so we can verify brain.py's
correlation logic actually works, without waiting for a real coincidence
between BaitTrace and ThreatLens to happen naturally.

Run this once, then run brain.py, and you should see a correlated alert.

Delete this file once you've confirmed the brain works - it's only for
this one test, not part of the deployed system.
"""

from shared_events import log_event

log_event(
    source="honeypot",
    ip="209.85.220.41",  # same IP that showed up in your ThreatLens test
    event_type="brute_force",
    detail="[TEST] Simulated: 47 failed SSH login attempts",
    severity="Malicious",
)

print("Test honeypot event inserted. Now run brain.py and watch for a correlated alert.")
