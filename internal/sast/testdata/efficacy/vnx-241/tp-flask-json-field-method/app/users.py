from flask import Flask, request

app = Flask(__name__)


@app.route("/users", methods=["POST"])
def create_user():
~>    username = request.json["username"].strip()
~>    role = request.get_json().get("role").lower()
    return {"username": username, "role": role}
