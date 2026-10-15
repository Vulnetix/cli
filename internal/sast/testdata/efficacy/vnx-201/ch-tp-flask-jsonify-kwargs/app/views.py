from flask import Blueprint, jsonify

from .models import User

bp = Blueprint("users", __name__)


@bp.route("/api/users/<int:uid>")
def get_user(uid):
    u = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(uid)
~>    return jsonify(username=u.username, password=u.password)
