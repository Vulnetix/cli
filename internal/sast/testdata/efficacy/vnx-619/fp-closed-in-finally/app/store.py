def delete_order(conn, order_id):
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM orders WHERE id = %s", (order_id,))
        conn.commit()
    finally:
        cur.close()


def rename(conn, old, new):
    cur = conn.cursor()
    cur.execute("UPDATE t SET name = %s WHERE name = %s", (new, old))
    cur.close()
