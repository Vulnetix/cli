from flask import Flask, redirect, request
from flask import session as flask_session

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
~>    flask_session["next"] = target
    return redirect("/login")
