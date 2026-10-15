from flask import Blueprint, request, jsonify
from .models import db, User

bp = Blueprint("users", __name__)


@bp.route("/api/profile", methods=["PUT"])
def update_profile():
    payload = request.get_json()
    user = User.query.get(payload["id"])
    user.display_name = payload.get("display_name")
~>    user.is_admin = request.json.get("is_admin", False)
    db.session.commit()
    return jsonify(ok=True)
