from flask import jsonify

from .models import User


def profile(uid):
    user = User.query.get(uid)
    # return jsonify({"password": user.password})  -- never do this
    return jsonify({"id": user.id, "name": user.name, "message": "Your password was updated"})


def masked(uid):
    user = User.query.get(uid)
    return jsonify({"name": user.name, "password": "********"})


def summary(uid):
    user = User.query.get(uid)
    return jsonify(user.to_public_dict())
