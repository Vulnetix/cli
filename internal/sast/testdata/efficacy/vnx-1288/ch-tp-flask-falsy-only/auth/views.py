from flask import Blueprint, request, redirect, flash

bp = Blueprint("auth", __name__)


@bp.route("/reset", methods=["POST"])
def reset_password():
    new = request.form.get("new_password")
~>    confirm = request.form.get("confirm_password")
    if not new or not confirm:
        flash("Both fields are required")
        return redirect("/reset")
    current_user.set_password(new)
    return redirect("/")
