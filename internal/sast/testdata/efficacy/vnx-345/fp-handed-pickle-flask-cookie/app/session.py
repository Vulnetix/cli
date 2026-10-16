import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    prefs = pickle.loads(base64.b64decode(request.cookies.get("prefs", "")))
    return render(prefs)


@app.route("/import", methods=["POST"])
def import_state():
    state = pickle.loads(
        request.get_data()
    )
    return {"ok": bool(state)}
