import helpers.db


def search(request):
    term = request.form.get("q")
    sql = f'SELECT title FROM posts WHERE title LIKE \'%{term}%\''
    con = helpers.db.get_connection()
    cur = con.cursor()
~>    cur.execute(sql)
    return cur.fetchall()


def lookup(cur, user):
    query = "SELECT * FROM accounts WHERE owner = '" + user + "'"
    print(query)
~>    cur.execute(query)
