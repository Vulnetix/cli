from flask import Blueprint, abort, jsonify

from .models import User

bp = Blueprint("profile", __name__)


@bp.route("/u/<username>")
def public_profile(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return jsonify(username=user.username, bio=user.bio, joined=user.created_at.isoformat())
