import pymysql

from app import config


def totals(customer_ids):
    out = {}
    for cid in customer_ids:
~>        conn = pymysql.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            database="sales",
        )
        with conn.cursor() as cur:
            cur.execute("SELECT SUM(total) FROM orders WHERE customer_id = %s", (cid,))
            out[cid] = cur.fetchone()[0]
        conn.close()
    return out
