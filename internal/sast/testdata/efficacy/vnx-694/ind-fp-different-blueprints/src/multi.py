from flask import Blueprint

admin = Blueprint("admin", __name__)
public = Blueprint("public", __name__)


@admin.route("/status")
def admin_status():
    return "admin"


@public.route("/status")
def public_status():
    return "public"
