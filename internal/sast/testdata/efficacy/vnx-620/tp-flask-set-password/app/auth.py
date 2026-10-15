from flask import Blueprint, request, redirect
from flask_login import current_user, login_required

bp = Blueprint("auth", __name__)


@bp.route("/change_password", methods=["POST"])
@login_required
def change_password():
    new_password = request.form["new_password"]
    confirm = request.form["confirm"]
    if new_password != confirm:
        return "mismatch", 400
~>    current_user.set_password(new_password)
    db.session.commit()
    return redirect("/profile")
