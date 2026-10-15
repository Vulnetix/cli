from flask import Flask, request, session, redirect
import flask

app = Flask(__name__)


@app.route("/next", methods=["GET"])
def remember_next():
~>    session["next_url"] = request.args.get("next")
    return redirect("/login")


@app.route("/pref", methods=["POST"])
def pref():
    value = request.cookies.get("pref", "default")
    bar = value.strip()
~>    flask.session[bar] = "12345"
    return "saved"
