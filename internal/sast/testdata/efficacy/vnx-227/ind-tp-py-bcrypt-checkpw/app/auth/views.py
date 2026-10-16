import bcrypt
from flask import request, session, redirect


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first_or_404()
~>    bcrypt.checkpw(request.form["password"].encode(), user.password_hash)
    session["uid"] = user.id
    return redirect("/")
