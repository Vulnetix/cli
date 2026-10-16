from flask import Blueprint, jsonify, request

from app.auth import issue_token, InvalidCredentials

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/login")
def login():
    data = request.get_json(force=True)
    try:
        token = issue_token(data["username"], data["password"])
    except InvalidCredentials:
~>        return jsonify(error="invalid credentials"), 200
    return jsonify(token=token)
