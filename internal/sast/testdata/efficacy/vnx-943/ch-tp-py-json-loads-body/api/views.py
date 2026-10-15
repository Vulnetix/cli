import json

from flask import Blueprint, request

from .db import mongo

bp = Blueprint("users", __name__)


@bp.post("/users/lookup")
def lookup():
    criteria = json.loads(request.data)
~>    user = mongo.db.users.find_one(criteria)
    if user is None:
        return {"error": "not found"}, 404
    return {"id": str(user["_id"])}
