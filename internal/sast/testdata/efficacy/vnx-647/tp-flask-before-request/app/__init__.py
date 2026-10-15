from flask import Flask, request, abort, session

app = Flask(__name__)


@app.before_request
def guard():
~>    if request.path.startswith("/admin") and not session.get("is_admin"):
        abort(403)
    path = request.path
~>    if path in ("/billing", "/billing/export") and "user_id" not in session:
        abort(401)
