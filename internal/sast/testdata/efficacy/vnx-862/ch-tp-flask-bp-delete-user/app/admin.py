from flask import Blueprint, jsonify
from .models import db, User

admin_bp = Blueprint("admin", __name__)


@admin_bp.route(
    "/users/<int:user_id>",
    methods=["DELETE"],
)
~>def remove_user(user_id):
    user = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify(deleted=user_id)
