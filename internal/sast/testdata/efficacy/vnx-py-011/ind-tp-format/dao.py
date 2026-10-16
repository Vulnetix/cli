def purge(cursor, token):
~>    cursor.execute("DELETE FROM sessions WHERE token = '{}'".format(token))
