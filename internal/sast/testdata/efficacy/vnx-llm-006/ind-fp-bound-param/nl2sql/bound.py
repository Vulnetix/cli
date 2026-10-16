def find(resp, cur):
    name = resp.choices[0].message.content.strip()
    cur.execute("SELECT id FROM customers WHERE name = ?", (name,))
    return cur.fetchall()
