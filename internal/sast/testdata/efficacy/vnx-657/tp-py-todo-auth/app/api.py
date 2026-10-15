from flask import Blueprint, jsonify

bp = Blueprint("admin", __name__)


@bp.route("/admin/users")
~># TODO: add authentication before release
def list_users():
    return jsonify(load_users())


def delete_user(uid):
~>    # FIXME: no authorization check here, any caller can delete
    users.delete(uid)
