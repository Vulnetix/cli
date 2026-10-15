from flask import Blueprint
from flask_security import roles_required, login_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/users")
@login_required
@roles_required("admin")
def users():
    return "users"


# @admin_bp.route("/admin/debug") was removed in 2.3
