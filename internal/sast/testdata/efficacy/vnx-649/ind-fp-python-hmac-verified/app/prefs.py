import base64
import hashlib
import hmac
import json

from flask import Flask, abort, request

app = Flask(__name__)
SECRET = app.config.get("PREFS_SECRET", b"")


@app.route("/account")
def account():
    value, _, sig = request.cookies.get("profile", "").partition(".")
    expected = hmac.new(SECRET, value.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(400)
    profile = json.loads(base64.b64decode(value))
    return {"plan": profile["plan"]}
