from flask import Blueprint, request, jsonify
from app.models import db, User

admin_bp = Blueprint("admin", __name__)


~>@admin_bp.route("/admin/delete_user", methods=["POST"])
def delete_user():
    user = User.query.get(request.form["id"])
    db.session.delete(user)
    db.session.commit()
    return jsonify(ok=True)
