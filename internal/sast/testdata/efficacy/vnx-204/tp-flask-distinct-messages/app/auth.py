from flask import Blueprint, jsonify, request

from .models import User

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user is None:
~>        return jsonify(error="User not found"), 401
    if not user.check_password(request.form["password"]):
        return jsonify(error="Incorrect password"), 401
    return jsonify(ok=True)
