from flask import Blueprint

bp = Blueprint("main", __name__)


@bp.route('/reports', methods=['GET'])
def reports():
    return "a"


~>@bp.route("/reports",  methods=["GET"])
def reports_v2():
    return "b"
