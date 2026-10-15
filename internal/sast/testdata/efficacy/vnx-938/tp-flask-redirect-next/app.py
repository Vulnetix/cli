from flask import Flask, redirect, request, session, url_for

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    session["user"] = request.form["user"]
~>    return redirect(request.args.get("next", "/"))


@app.route("/out")
def outbound():
    target = request.args["url"]
~>    return redirect(target, code=302)


@app.route("/go")
def go():
    dest = request.values.get("to")
    full = dest.strip()
~>    return redirect(
        full)


@app.route("/home")
def home():
    return redirect(url_for("index"))
