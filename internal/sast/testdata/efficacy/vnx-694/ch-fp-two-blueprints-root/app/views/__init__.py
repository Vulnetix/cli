from flask import Blueprint

admin = Blueprint("admin", __name__, url_prefix="/admin")
public = Blueprint("public", __name__)


@admin.route("/")
def admin_index():
    return "admin"


@public.route("/")
def public_index():
    return "home"
