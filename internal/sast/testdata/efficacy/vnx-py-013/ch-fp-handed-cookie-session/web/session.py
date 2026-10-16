import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    raw = request.cookies.get("prefs", "")
    prefs = pickle.loads(base64.b64decode(raw))
    return {"theme": prefs.get("theme")}
