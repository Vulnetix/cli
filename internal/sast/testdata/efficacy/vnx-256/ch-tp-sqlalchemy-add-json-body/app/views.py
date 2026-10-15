from flask import Blueprint, request, jsonify

from .models import db, User

bp = Blueprint("users", __name__)


@bp.route("/api/users", methods=["POST"])
def create_user_api():
    data = request.get_json()
~>    db.session.add(User(email=data["email"], password=data["password"]))
    db.session.commit()
    return jsonify(ok=True), 201
