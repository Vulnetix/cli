import base64
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def index():
    data = request.cookies.get("prefs")
~>    prefs = pickle.loads(base64.b64decode(data))
    return render(prefs)
