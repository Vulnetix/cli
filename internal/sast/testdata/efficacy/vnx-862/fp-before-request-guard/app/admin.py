from flask import Blueprint, abort, session

from .models import User, db

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def require_admin():
    if not session.get("is_admin"):
        abort(403)


@bp.route("/users/<int:uid>/delete", methods=["POST"])
def delete_user(uid):
    User.query.filter_by(id=uid).delete()
    db.session.commit()
    return "", 204


@bp.route("/")
def dashboard():
    return "admin"
