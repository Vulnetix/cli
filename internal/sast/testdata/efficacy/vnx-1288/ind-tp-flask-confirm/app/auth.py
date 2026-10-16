from flask import Flask, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    username = request.form["username"]
    password = request.form["password"]
~>    confirm = request.form["confirm_password"]
    db.insert(username, generate_password_hash(password))
    return "ok", 201
