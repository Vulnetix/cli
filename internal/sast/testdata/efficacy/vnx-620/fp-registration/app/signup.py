@bp.route("/register", methods=["POST"])
def register():
    user = User(username=request.form["username"])
    user.set_password(request.form["password"])
    db.session.add(user)
    db.session.commit()
    return redirect("/login")
