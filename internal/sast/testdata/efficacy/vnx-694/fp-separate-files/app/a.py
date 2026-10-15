from flask import Blueprint

bp = Blueprint("a", __name__)


@bp.route("/status")
def status():
    return "a"
