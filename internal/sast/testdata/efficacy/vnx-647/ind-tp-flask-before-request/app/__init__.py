from flask import Flask, abort, request, session

app = Flask(__name__)


@app.before_request
def protect_admin():
~>    if request.path.startswith("/admin") and not session.get("is_admin"):
        abort(403)
