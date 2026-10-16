import jwt
from flask import Flask, request, g

app = Flask(__name__)
KEY = "loaded-from-env"


@app.before_request
def load_claims():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, KEY, algorithms=["HS256"])
~>    g.claims = {**claims, **request.json}


@app.route("/prefs", methods=["POST"])
def prefs():
    body = request.get_json()
~>    session.update(body)
    return {"ok": True}
