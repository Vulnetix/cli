"""One-off migration: copy feature flags into the new table."""
import sqlite3

conn = sqlite3.connect("app.db")
cur = conn.cursor()
cur.execute("INSERT INTO feature_flag_v2 (name, enabled) SELECT name, enabled FROM feature_flag")
conn.commit()
print("migrated", cur.rowcount, "flags")
