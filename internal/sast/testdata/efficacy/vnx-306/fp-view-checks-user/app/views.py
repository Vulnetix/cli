from flask import Flask, abort
from flask_login import current_user

app = Flask(__name__)


@app.route("/admin/stats")
def stats():
    if not current_user.is_admin:
        abort(403)
    return "stats"
