import bcrypt
from flask import Blueprint, abort, request

from .models import User

bp = Blueprint("auth", __name__)
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


@bp.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    hashed = user.password_hash if user else DUMMY_HASH
    ok = bcrypt.checkpw(request.form["password"].encode(), hashed)
    if user is None or not ok:
        abort(401)
    return "ok"
