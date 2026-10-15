from flask import Blueprint

bp = Blueprint("b", __name__)


@bp.route("/status")
def status():
    return "b"
