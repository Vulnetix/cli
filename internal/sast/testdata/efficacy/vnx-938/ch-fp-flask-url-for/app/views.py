from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/logout")
def logout():
    lang = request.args.get("lang", "en")
    return redirect(url_for("index", lang=lang))


@app.route("/old")
def old():
    return redirect("/new", code=301)
