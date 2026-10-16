from flask import Blueprint, jsonify

from .models import User, db

bp = Blueprint("ops", __name__)


~>@bp.route(
    "/administration/users/<int:uid>/promote",
    methods=["POST"],
)
def promote(uid):
    user = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(uid)
    user.role = "owner"
    db.session.commit()
    return jsonify(ok=True)
