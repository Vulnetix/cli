import os

from flask import Flask, request, session

app = Flask(__name__)

ADMIN_MODE = os.environ.get("ADMIN_MODE", "off")


@app.route("/settings/contact", methods=["POST"])
def update_contact():
    admin_email = request.form.get("admin_email")
    role = session.get("role")
    if role != "owner":
        return "forbidden", 403
    save_contact(admin_email)
    return "ok"
