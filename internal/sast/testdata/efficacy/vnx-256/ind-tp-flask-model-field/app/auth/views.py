from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db

bp = Blueprint("account", __name__)


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        newpassword = request.form["newpassword"]
        confirm = request.form["confirm"]
        if newpassword != confirm:
            flash("Passwords do not match")
            return redirect(url_for("account.change_password"))
~>        current_user.password = newpassword
        db.session.commit()
        flash("Password updated")
    return render_template("account/password.html")
