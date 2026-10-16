from flask import Blueprint, request, jsonify

bp = Blueprint("users", __name__)


@bp.post("/users")
def create_user():
    data = request.get_json()
    email = data["email"]
~>    normalized = email.lower()
~>    username = request.json.get("username").strip()
    return jsonify(email=normalized, username=username)
