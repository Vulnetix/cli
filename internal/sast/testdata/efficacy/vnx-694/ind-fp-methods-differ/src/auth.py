from flask import Flask

app = Flask(__name__)


@app.route("/login", methods=["GET"])
def login_form():
    return "form"


@app.route("/login", methods=["POST"])
def login_submit():
    return "ok"
