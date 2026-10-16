from flask import Flask, request, jsonify

app = Flask(__name__)

DEBUG_TOOLBAR = False
THEME = "light"


@app.route("/admin/settings", methods=["POST"])
def update_settings():
    for key, value in request.form.items():
~>        globals()[key] = value
    return jsonify(ok=True)


@app.route("/admin/setting")
def read_setting():
    name = request.args.get("name")
~>    current = globals().get(name)
    return jsonify(value=str(current))
