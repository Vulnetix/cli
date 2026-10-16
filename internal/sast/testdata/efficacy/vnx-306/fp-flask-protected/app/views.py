from flask import Flask, abort, render_template, session
from flask_login import current_user, login_required

from .auth import admin_required

app = Flask(__name__)


@app.route("/admin/users")
@login_required
def list_users():
    return render_template("admin/users.html")


@admin_required
@app.route("/admin/audit")
def audit():
    return render_template("admin/audit.html")


@app.route("/admin/export")
def export():
    if not current_user.is_admin:
        abort(403)
    return render_template("admin/export.html")


@app.route("/admin/legacy")
def legacy():
    if session.get("role") != "admin":
        abort(401)
    return "ok"


@app.route("/products")
def products():
    return render_template("products.html")
