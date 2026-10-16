from flask import Flask, request

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    name = request.form["name"]
    email = request.form["email"]
    with open("signups.csv", "a") as f:
~>        f.write(f"{name},{email}\n")
    return "ok"
