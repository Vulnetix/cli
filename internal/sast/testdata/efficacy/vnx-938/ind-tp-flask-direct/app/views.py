from flask import Blueprint, redirect, request

bp = Blueprint("auth", __name__)


@bp.route("/login/done")
def done():
~>    return redirect(request.args.get("next", "/"))
