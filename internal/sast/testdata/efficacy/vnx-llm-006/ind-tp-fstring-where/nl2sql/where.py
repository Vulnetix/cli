def orders(msg, cur):
    where_clause = msg.content[0].text
~>    cur.execute(f"SELECT id, name FROM orders WHERE {where_clause}")
    return cur.fetchall()
