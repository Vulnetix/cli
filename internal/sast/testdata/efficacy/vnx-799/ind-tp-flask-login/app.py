from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash

app = Flask(__name__)


~>@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return "form"
    user = lookup(request.form["username"])
    if user and check_password_hash(user.pw, request.form["password"]):
        return jsonify(ok=True)
    return jsonify(ok=False), 401
