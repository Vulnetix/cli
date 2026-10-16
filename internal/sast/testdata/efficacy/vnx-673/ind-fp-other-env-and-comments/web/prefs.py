import os

from flask import Flask, request

app = Flask(__name__)


@app.post("/prefs")
def prefs():
    theme = request.args.get("theme", "light")
    os.environ["APP_THEME"] = theme
    os.environ["TZ"] = request.form.get("tz", "UTC")
    # os.chroot(request.args.get("dir")) would let a client pick the jail
    note = "sys.path.insert(0, request.args['p']) is unsafe"
    return note
