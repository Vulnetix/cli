from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from .models import User

bp = Blueprint("api", __name__)


@bp.route("/me")
@login_required
def me():
    data = dict(current_user.__dict__)
    data.pop("_sa_instance_state", None)
~>    return jsonify(data)


@bp.route("/users/<int:uid>")
def show(uid):
    user = @@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(uid)
~>    return jsonify(vars(user))
