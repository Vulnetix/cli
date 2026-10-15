from flask import Blueprint, request

bp = Blueprint("accounts", __name__)


@bp.post("/accounts/search")
def search():
    params = request.get_json(silent=True) or {}
~>    found = Account.query.filter_by(**params).first()
    return {"id": found.id if found else None}
