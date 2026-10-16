from flask import Blueprint, abort, g

admin = Blueprint("admin", __name__, url_prefix="/admin")


@admin.before_request
def require_staff():
    if g.user is None or not g.user.is_staff:
        abort(403)


@admin.route("/settings", methods=["POST"])
def save_settings():
    return {"saved": True}
