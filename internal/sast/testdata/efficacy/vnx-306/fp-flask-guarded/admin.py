from flask import Blueprint, abort, session

admin_bp = Blueprint("admin", __name__)


@admin_bp.before_request
def only_admins():
    if session.get("role") != "admin":
        abort(403)


@admin_bp.route("/admin/purge", methods=["POST"])
def purge():
    return "", 204
