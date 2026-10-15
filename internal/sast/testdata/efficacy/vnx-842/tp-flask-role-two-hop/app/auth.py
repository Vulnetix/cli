from flask import Blueprint, request, jsonify

from .models import User, db

bp = Blueprint("auth", __name__)


@bp.route("/signup", methods=["POST"])
def signup():
    payload = request.get_json()
    chosen = payload.get("role", "member")
~>    user = User(email=payload["email"], role=chosen)
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id), 201


@bp.route("/profile", methods=["POST"])
def update_profile():
    account = User.query.get(request.form["id"])
~>    account.is_staff = request.form.get("is_staff") == "1"
    db.session.commit()
    return jsonify(ok=True)
