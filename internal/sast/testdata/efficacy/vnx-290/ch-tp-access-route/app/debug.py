from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/debug/vars")
def debug_vars():
~>    if request.access_route[0] != "127.0.0.1":
        abort(404)
    return dump_state()
