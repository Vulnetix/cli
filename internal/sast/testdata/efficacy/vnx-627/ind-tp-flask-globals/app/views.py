from flask import Flask, request

app = Flask(__name__)
DEBUG_LEVEL = 0


@app.route("/config", methods=["POST"])
def update_config():
    for key, value in request.form.items():
~>        globals()[key] = value
    return "ok"
