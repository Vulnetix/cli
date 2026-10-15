from flask import jsonify
from flask_login import current_user

SENSITIVE = {"password_hash", "_sa_instance_state"}


def me():
    data = {k: v for k, v in current_user.__dict__.items() if k not in ("password_hash", "otp_secret")}
    return jsonify(data)


def settings(args):
    return jsonify(vars(args))


def debug_user(user):
    data = dict(vars(user))
    data.pop("password", None)
    return jsonify(data)
