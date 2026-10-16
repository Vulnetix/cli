from flask import Blueprint, request, abort, session
from extensions import mongo

bp = Blueprint("auth", __name__)


@bp.post("/login")
def login():
    payload = request.get_json()
    if payload is None:
        abort(400)
~>    account = mongo.db.users.find_one({"email": payload["email"], "password_hash": payload["password"]})
    if account is None:
        abort(401)
    session["uid"] = str(account["_id"])
    return {"ok": True}
