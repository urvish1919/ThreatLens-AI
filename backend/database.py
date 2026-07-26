import sqlite3

connection = sqlite3.connect("threatlens.db", check_same_thread=False)

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT,
    target TEXT,
    threat_score INTEGER,
    status TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

connection.commit()