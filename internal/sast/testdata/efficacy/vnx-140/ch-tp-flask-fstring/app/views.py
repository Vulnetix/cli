from flask import Flask, request

app = Flask(__name__)


@app.route("/subscribe", methods=["POST"])
def subscribe():
    name = request.form["name"]
    email = request.form.get("email", "")
    with open("subscribers.csv", "a") as fh:
~>        fh.write(f"{name},{email}\n")
    return "ok"
