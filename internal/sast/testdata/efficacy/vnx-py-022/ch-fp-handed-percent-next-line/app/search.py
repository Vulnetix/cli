def search(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = '%s'"
                   % username)
    return cursor.fetchall()
