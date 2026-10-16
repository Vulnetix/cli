from flask import Blueprint, abort, jsonify

from .auth import admin_required
from .models import User

bp = Blueprint("admin", __name__)


@bp.route("/admin/users/<username>")
@admin_required
def show_user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify(error="User not found"), 404
    return jsonify(id=user.id, username=user.username, created=user.created_at.isoformat())
