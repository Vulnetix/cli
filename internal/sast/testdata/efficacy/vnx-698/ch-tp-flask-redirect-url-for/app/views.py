from flask import redirect, session, url_for, render_template


def dashboard():
    if "user_id" not in session:
~>        redirect(url_for("auth.login"))
    return render_template("dashboard.html")
