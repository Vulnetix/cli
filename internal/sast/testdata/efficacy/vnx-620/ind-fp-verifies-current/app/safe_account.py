from flask import Blueprint, request, abort
from flask_login import current_user

bp = Blueprint("safe", __name__)


@bp.route("/account/change_password", methods=["POST"])
def change_password():
    old = request.form["old_password"]
    if not current_user.check_password(old):
        abort(403)
    current_user.set_password(request.form["new_password"])
    return "ok"
