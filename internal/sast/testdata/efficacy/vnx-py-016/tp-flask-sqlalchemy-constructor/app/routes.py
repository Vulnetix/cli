from flask import Blueprint, jsonify, request

from .extensions import db
from .models import Account

bp = Blueprint("accounts", __name__)


@bp.post("/accounts")
def create_account():
~>    account = Account(**request.get_json())
    db.session.add(account)
    db.session.commit()
    return jsonify(id=account.id)


@bp.post("/accounts/form")
def create_account_form():
    data = request.form.to_dict()
~>    account = Account(**data)
    db.session.add(account)
    db.session.commit()
    return jsonify(id=account.id)
