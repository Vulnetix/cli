import secrets

from flask import Flask, request, session

app = Flask(__name__)
cache = {}


@app.route("/")
def index():
    session["visits"] = session.get("visits", 0) + 1
    session["csrf"] = secrets.token_hex(16)
    cache[request.args.get("k", "")] = 1
    session.pop("next", None)
    return "ok"
