from flask import Flask, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)


@app.route("/reset", methods=["POST"])
def reset():
    password = request.form["password"]
~>    confirm = request.form.get("confirm_password")
    if len(password) < 12:
        return "too short", 400
    save(generate_password_hash(password))
    return "ok"
