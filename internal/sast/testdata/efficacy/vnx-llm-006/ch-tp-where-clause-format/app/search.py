def search(cursor, client, filters):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": filters}])
    where = resp.choices[0].message.content
~>    cursor.execute("SELECT id, name FROM products WHERE {} LIMIT 50".format(where))
    return cursor.fetchall()
