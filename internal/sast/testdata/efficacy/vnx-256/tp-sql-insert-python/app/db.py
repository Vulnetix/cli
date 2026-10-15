def add_user(request, cur):
    name = request.form["name"]
    pw = request.form["password"]
~>    cur.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, pw))
    cur.execute(
~>        "UPDATE users SET password = %s WHERE id = %s",
        (request.form["password"], request.form["id"]),
    )
