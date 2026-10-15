from flask import Blueprint, Flask, abort
from flask_login import current_user, login_required

from .decorators import admin_required
from .models import User, db

app = Flask(__name__)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    db.session.delete(@@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(user_id))
    return "", 204


@app.route("/admin/stats")
def stats():
    if not current_user.is_admin:
        abort(403)
    return {"users": User.query.count()}
