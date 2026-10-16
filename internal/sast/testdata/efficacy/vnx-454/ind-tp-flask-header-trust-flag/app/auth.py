from flask import Flask, g, request, abort

app = Flask(__name__)


@app.before_request
def load_identity():
    # The edge proxy is supposed to set these, but nothing strips them from
    # requests that reach the app directly.
~>    g.authenticated = request.headers.get("X-Authenticated", False)
    g.request_id = request.headers.get("X-Request-Id")


@app.route("/admin/users")
def list_users():
    if not g.authenticated:
        abort(401)
    return {"users": []}
