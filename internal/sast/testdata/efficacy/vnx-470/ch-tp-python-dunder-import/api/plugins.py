from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/plugin")
def load_plugin():
    module_name = request.args["module"]
~>    mod = __import__(module_name)
    return jsonify(mod.describe())
