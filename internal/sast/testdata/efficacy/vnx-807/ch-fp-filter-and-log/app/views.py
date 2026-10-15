import logging

from flask import request, jsonify

from .models import User

log = logging.getLogger(__name__)


def list_users():
    role = request.args.get("role")
    log.info("listing users with role %s", role)
    users = User.query.filter_by(role=role).all() if role else User.query.all()
    return jsonify([u.to_dict() for u in users])


def theme():
    if request.cookies.get("theme") == "dark":
        return "dark.css"
    return "light.css"
