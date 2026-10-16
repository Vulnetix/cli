from flask import Blueprint, jsonify
from flask_caching import Cache
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_login import current_user, login_required

cache = Cache()
bp = Blueprint("account", __name__)


@bp.route("/account/summary")
@login_required
~>@cache.cached(timeout=300)
def account_summary():
    return jsonify(email=current_user.email, plan=current_user.plan)


@bp.route("/api/me")
@jwt_required()
def me():
    resp = jsonify(id=get_jwt_identity())
~>    resp.headers["Cache-Control"] = "max-age=600"
    return resp
