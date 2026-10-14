TABLE = "audit_log"
COLUMNS = "id, ts, actor"


def migrate(cur):
    cur.execute("SELECT " + COLUMNS + " FROM " + TABLE)
    cur.execute(f"DELETE FROM {TABLE} WHERE ts < date('now', '-90 days')")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ts ON %s (ts)" % TABLE)
