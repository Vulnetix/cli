from flask import Blueprint

bp = Blueprint("account", __name__)


@bp.route("/account/delete", methods=["POST"])
def delete_account():
    return do_delete()


~>@bp.route( '/account/delete', methods=['POST'] )
def delete_account_v2():
    require_reauth()
    return do_delete()
