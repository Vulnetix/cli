from flask import Flask, jsonify
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/orders")
@login_required
def orders():
    resp = jsonify(current_user.orders)
    resp.headers["Cache-Control"] = "max-age=0, must-revalidate"
    return resp


@app.route("/robots.txt")
def robots():
    resp = app.send_static_file("robots.txt")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp
