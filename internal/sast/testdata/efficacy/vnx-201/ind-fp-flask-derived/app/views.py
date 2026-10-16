from flask import Blueprint, jsonify

from .models import User

bp = Blueprint("users", __name__)


@bp.route("/api/users/<int:user_id>")
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    # password_hash stays server side; only report whether one is set
    return jsonify(
        {
            "id": user.id,
            "email": user.email,
            "password_set": bool(user.password_hash),
            "password_updated_at": user.password_updated_at.isoformat(),
        }
    )
