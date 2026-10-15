from flask import Flask, Blueprint, request, session

app = Flask(__name__)
bp = Blueprint("account", __name__)


~>@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and check(request.form["user"], request.form["pw"]):
        session["user"] = request.form["user"]
    return "ok"


~>@bp.post('/forgot-password')
def forgot():
    send_reset(request.form["email"])
    return "sent"


@app.route("/about")
def about():
    return "about"
