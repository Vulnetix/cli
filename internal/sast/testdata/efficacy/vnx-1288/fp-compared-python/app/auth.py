import hmac

from flask import request


def reset():
    password = request.form["password"]
    confirm = request.form.get("confirm_password", "")
    if not hmac.compare_digest(password, confirm):
        return "mismatch", 400
    return "ok"


def signup():
    data = request.get_json()
    if data["password"] != data["password_confirmation"]:
        return {"error": "mismatch"}, 400
    return {}
