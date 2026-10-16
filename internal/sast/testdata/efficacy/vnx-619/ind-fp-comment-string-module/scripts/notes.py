import sqlite3

# cur = conn.cursor()   old way, never do this
HELP = "cur = conn.cursor() must be closed"
conn = sqlite3.connect(":memory:")
conn.close()
