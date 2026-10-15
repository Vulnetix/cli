from flask import Flask, abort, redirect, url_for

app = Flask(__name__)


@app.route("/old")
def old():
    return redirect(url_for("new"))


@app.route("/check")
def check():
    resp = redirect("/next")
    resp.set_cookie("seen", "1")
    if missing():
        abort(redirect("/login"))
    return resp
