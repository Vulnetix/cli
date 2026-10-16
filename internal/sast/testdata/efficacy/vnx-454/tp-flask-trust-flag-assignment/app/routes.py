from flask import Flask, g, request, abort

app = Flask(__name__)


@app.before_request
def load_flags():
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    is_admin = request.cookies.get("is_admin") == "true"
~>    g.authenticated = request.headers.get("X-Authenticated") == "yes"
    g.is_admin = is_admin


@app.route("/admin")
def admin():
    if not g.is_admin:
        abort(403)
    return "ok"
