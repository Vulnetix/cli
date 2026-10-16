from flask import Blueprint, Flask, jsonify

from .cache import cache
from .models import User, db

app = Flask(__name__)
reports = Blueprint("reports", __name__)


~>@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    db.session.delete(@@sample:U[s]er[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(user_id))
    db.session.commit()
    return "", 204


~>@reports.get('/admin/export')
@cache.cached(timeout=60)
def export_all():
    return jsonify([u.to_dict() for u in User.query.all()])


@app.route("/about")
def about():
    return "about"
