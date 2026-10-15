from flask import Blueprint, abort, session

admin = Blueprint("admin", __name__)


@admin.before_request
def guard():
    if not session.get("is_admin"):
        abort(403)


@admin.route("/admin/users")
def users():
    return "users"
