from flask import Flask
from flask_login import login_required

from .auth import admin_required

app = Flask(__name__)


@app.route("/admin/users")
@login_required
def users():
    return "users"


@app.route("/admin/settings", methods=["POST"])
@admin_required
def settings():
    return "saved"
