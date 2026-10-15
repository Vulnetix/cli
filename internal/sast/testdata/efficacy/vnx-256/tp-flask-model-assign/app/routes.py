@app.route("/changepassword", methods=["POST"])
def change_password():
    username = request.form["username"]
    newpassword = request.form["newpassword"]
    u = User.query.filter(User.username == username).first()
~>    u.password = newpassword
    db_session.commit()


@app.route("/register", methods=["POST"])
def register():
    user = User(username=request.form["username"])
~>    user.password = request.form.get("password")
    db_session.add(user)
