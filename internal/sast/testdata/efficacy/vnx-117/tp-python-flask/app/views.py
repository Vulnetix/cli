import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
~>    logger.warning("failed login for %s", username)
~>    app.logger.info(f"login attempt from {request.headers.get('X-Forwarded-For')}")
~>    logging.error("bad token: " + request.args["token"])
    return "no", 401
