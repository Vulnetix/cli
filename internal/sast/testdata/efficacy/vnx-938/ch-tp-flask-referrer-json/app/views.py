from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/lang/<code>")
def set_lang(code):
~>    return redirect(request.referrer or url_for("index"))


@app.route("/api/continue", methods=["POST"])
def cont():
    payload = request.get_json()
    target = payload["return_to"]
~>    return redirect(target)
