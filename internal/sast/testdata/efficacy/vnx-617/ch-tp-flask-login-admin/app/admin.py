from flask import Blueprint, jsonify
from flask_login import current_user, login_required

bp = Blueprint("admin", __name__)


@bp.route("/admin/users")
@login_required
def users():
~>    assert current_user.is_admin
    return jsonify([u.email for u in User.query.all()])


@bp.route("/admin/users/<int:uid>", methods=["DELETE"])
def delete_user(uid):
~>    assert can_delete_user(current_user, uid), "forbidden"
    User.query.filter_by(id=uid).delete()
    return "", 204
