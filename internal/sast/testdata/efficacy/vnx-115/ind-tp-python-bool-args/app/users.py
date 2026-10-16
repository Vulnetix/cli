from flask import Blueprint, jsonify, request

from .models import User

bp = Blueprint("users", __name__)


@bp.route("/users")
def list_users():
~>    include_deleted = bool(request.args.get("include_deleted"))
    query = User.query
    if not include_deleted:
        query = query.filter_by(deleted=False)
    return jsonify([u.to_dict() for u in query.all()])


@bp.route("/settings", methods=["POST"])
def save_settings():
    notify = request.form.get("email_notifications")
~>    current_user.email_notifications = bool(notify)
~>    current_user.dark_mode = bool(request.cookies.get("dark_mode"))
    return "", 204
