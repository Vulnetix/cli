def answer(resp, cursor):
    sql = resp.choices[0].message.content.strip()
~>    cursor.execute(sql)
    return cursor.fetchall()
