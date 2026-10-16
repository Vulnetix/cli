from flask import Blueprint, abort, redirect, request

from ..models import User, db
from ..tokens import verify_reset_token

bp = Blueprint("reset", __name__)


@bp.route("/reset_password/<token>", methods=["POST"])
def reset_password(token):
    user_id = verify_reset_token(token)
    if user_id is None:
        abort(400)
    user = User.query.get_or_404(user_id)
    user.set_password(request.form["password"])
    db.session.commit()
    return redirect("/login")
