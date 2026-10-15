import contextlib
import csv

import pymysql


def export_rows(conn, out_path):
    with contextlib.ExitStack() as stack:
        cur = conn.cursor()
        stack.callback(cur.close)
        cur.execute("SELECT id, email FROM accounts")
        with open(out_path, "w", newline="") as fh:
            csv.writer(fh).writerows(cur)


def export_audit(conn, out_path):
    with contextlib.ExitStack() as stack:
        audit_cur = conn.cursor()
        stack.enter_context(contextlib.closing(audit_cur))
        audit_cur.execute("SELECT * FROM audit")
        return audit_cur.fetchall()
