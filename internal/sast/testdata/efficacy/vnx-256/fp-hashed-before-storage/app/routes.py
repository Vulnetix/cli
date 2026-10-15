from werkzeug.security import generate_password_hash


def change_password(request, cur):
    newpassword = request.form["newpassword"]
    u.password = generate_password_hash(newpassword)
    pw = request.form["password"]
    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
    cur.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, pw_hash))
    User.objects.create_user(username=request.POST["username"], password=request.POST["password"])
    user.set_password(request.POST["password"])
    user.password = make_password(request.POST["password"])
