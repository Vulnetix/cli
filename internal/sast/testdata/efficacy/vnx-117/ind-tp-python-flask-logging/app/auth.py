import logging

from flask import Blueprint, current_app, request

bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    if not check_password(username, request.form.get("password", "")):
~>        logger.warning("failed login for %s", username)
        return "nope", 401
~>    current_app.logger.info(f"login ok from {request.headers.get('X-Forwarded-For')}")
    return "ok"


@bp.route("/search")
def search():
    term = request.args.get("q", "")
    normalized = term.strip()
~>    logging.info("search: " + normalized)
    return run_search(normalized)
