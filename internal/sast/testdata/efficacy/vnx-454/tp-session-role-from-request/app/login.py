from flask import request, session, redirect


def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user is None:
        return redirect("/login")
    session["user_id"] = user.id
~>    session["role"] = request.form.get("role", "user")
    return redirect("/")


def switch_role():
    wanted = request.args.get("role")
~>    session['role'] = wanted
    return redirect("/")
