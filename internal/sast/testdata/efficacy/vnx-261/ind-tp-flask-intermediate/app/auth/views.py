import base64

from flask import Blueprint, request, jsonify

from app.models import db, Account

bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    raw = request.form.get("password")
~>    obscured = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    acct = Account(username=username, credential=obscured)
    db.session.add(acct)
    db.session.commit()
    return jsonify({"id": acct.id}), 201
