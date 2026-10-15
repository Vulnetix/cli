import sqlite3


def logs_above(db_path, min_level):
    conn = sqlite3.connect(db_path)
    sql = "SELECT msg, level FROM logs WHERE level > :lvl"
~>    rows = conn.execute(sql, {"lvl": min_level}).fetchall()
    conn.close()
    return rows
