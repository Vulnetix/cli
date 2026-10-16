import bcrypt
from flask import Blueprint, abort, jsonify, request, session

from .models import User

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
~>    if user is None:
        return jsonify(error="Invalid credentials"), 401
    if not bcrypt.checkpw(request.form["password"].encode(), user.password_hash):
        return jsonify(error="Invalid credentials"), 401
    session["uid"] = user.id
    return jsonify(ok=True)
