import psycopg2


def orders_for(conn, user_id):
    cur = conn.cursor()
~>    cur.execute(f"SELECT * FROM orders WHERE user_id = {user_id}")
    return cur.fetchall()
