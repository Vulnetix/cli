from flask import Flask, request

app = Flask(__name__)
THEME = "light"


@app.route("/setting")
def setting():
~>    return str(globals()[request.args.get("name")])


@app.route("/set", methods=["POST"])
def set_value():
    name = request.form["name"]
    value = request.form["value"]
~>    globals()[name] = value
    return "ok"
