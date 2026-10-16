from flask import Blueprint, render_template, request, redirect, url_for

from app.accounts import create_account, InvalidSignup

signup_bp = Blueprint("signup", __name__)


@signup_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            create_account(request.form)
        except InvalidSignup as e:
            return render_template("signup.html", error=str(e), form=request.form)
        return redirect(url_for("home"))
    return render_template("signup.html")
