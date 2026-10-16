from flask import Blueprint, abort, request

bp = Blueprint("admin", __name__)

ALLOWED_IPS = {"10.0.0.5", "10.0.0.6"}


@bp.before_request
def restrict_to_office():
    real_ip = request.headers.get("X-Real-IP", "")
~>    if real_ip not in ALLOWED_IPS:
        abort(403)
