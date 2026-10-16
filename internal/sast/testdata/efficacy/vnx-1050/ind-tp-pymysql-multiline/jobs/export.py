import pymysql
import config


def export_all(customer_ids):
    for cid in customer_ids:
~>        conn = pymysql.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASS,
            database="sales",
        )
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM invoices WHERE customer = %s", (cid,))
            write_rows(cid, cur.fetchall())
        conn.close()
