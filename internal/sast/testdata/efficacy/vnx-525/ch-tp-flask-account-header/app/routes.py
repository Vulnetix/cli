from flask import Flask, jsonify
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/account")
@login_required
def account():
    resp = jsonify(email=current_user.email, plan=current_user.plan)
~>    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp
