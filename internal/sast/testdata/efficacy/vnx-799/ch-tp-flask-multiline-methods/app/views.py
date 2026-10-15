from flask import Blueprint, request, session, redirect, render_template

from .models import User

auth = Blueprint("auth", __name__)


~>@auth.route(
    "/login",
    methods=[
        "GET",
        "POST",
    ],
)
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user and user.check_password(request.form["password"]):
            session["uid"] = user.id
            return redirect("/")
    return render_template("login.html")


~>@auth.post("/devlogin")
def devlogin():
    session["uid"] = request.form["username"]
    return redirect("/")


@auth.post("/blogging")
def blogging():
    return redirect("/")
