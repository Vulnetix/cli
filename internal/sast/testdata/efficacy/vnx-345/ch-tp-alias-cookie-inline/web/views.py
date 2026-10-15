import base64
import cPickle as cp

from flask import Flask, request

app = Flask(__name__)


@app.route("/prefs")
def prefs():
~>    p = cp.loads(base64.b64decode(request.cookies.get("prefs", "")))
    return p.get("theme", "light")
