from flask import Blueprint, jsonify
from flask_login import login_required

from .models import User

bp = Blueprint("users", __name__)


@bp.route("/api/users/<int:user_id>")
@login_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
~>    return jsonify({"id": user.id, "email": user.email, "password_hash": user.password_hash})


@bp.route("/api/users/<int:user_id>/raw")
@login_required
def get_user_raw(user_id):
    u = User.query.get_or_404(user_id)
~>    return jsonify(u.__dict__)
