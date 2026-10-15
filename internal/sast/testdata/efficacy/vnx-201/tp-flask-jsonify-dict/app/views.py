from flask import Blueprint, jsonify, request

from .models import User

bp = Blueprint("users", __name__)


@bp.route("/api/user/<int:uid>")
def get_user(uid):
    user = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(uid)
~>    return jsonify({"id": user.id, "name": user.name, "password_hash": user.password_hash})


@bp.route("/api/profile")
def profile():
    u = User.query.filter_by(username=request.args["u"]).first()
~>    return jsonify(u.__dict__)
