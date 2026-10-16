from flask import Blueprint, abort, flash, redirect, request, url_for
from flask_login import current_user, login_required

from .extensions import db

bp = Blueprint("account", __name__)


@bp.route("/account/change_password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form["old_password"]
    new_password = request.form["new_password"]
    if not current_user.check_password(old_password):
        abort(403)
    current_user.set_password(new_password)
    db.session.commit()
    flash("Password updated")
    return redirect(url_for("account.settings"))
