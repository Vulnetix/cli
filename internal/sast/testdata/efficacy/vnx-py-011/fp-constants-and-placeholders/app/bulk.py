TABLE = "audit_log"
COLUMNS = "id, actor, action"
PURGE_SQL = "DELETE FROM audit_log WHERE created < now() - interval '90 days'"


def purge(cur, ids):
    placeholders = ",".join("?" * len(ids))
    cur.execute(f"DELETE FROM {TABLE} WHERE id IN ({placeholders})", ids)
    cur.execute("SELECT * FROM t WHERE id IN (%s)" % ",".join(["%s"] * len(ids)), ids)
    cur.execute(f"SELECT {COLUMNS} FROM {TABLE}")
    cur.execute("SELECT " + COLUMNS + " FROM audit_log")
    cur.execute(PURGE_SQL)
    cur.execute("VACUUM " + "audit_log")
