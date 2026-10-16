import hashlib

from flask import Blueprint, request

from .models import User, db

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
~>    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    db.session.add(User(username=username, password_hash=password_hash))
    db.session.commit()
    return "", 201
