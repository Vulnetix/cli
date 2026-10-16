from flask import Flask, request

app = Flask(__name__)


@app.route("/pay", methods=["POST"])
def pay():
~>    assert request.form["amount"].isdigit()
    return "ok"
