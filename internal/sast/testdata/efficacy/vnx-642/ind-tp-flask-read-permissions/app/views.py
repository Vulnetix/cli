from flask import Blueprint, render_template, request

bp = Blueprint("dashboard", __name__)


@bp.route("/dashboard")
def dashboard():
~>    perms = request.cookies.get("permissions", "")
    widgets = load_widgets(perms.split(","))
    return render_template("dashboard.html", widgets=widgets)
