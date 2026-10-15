import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/locale", methods=["POST"])
def set_locale():
~>    os.environ["LANG"] = request.form.get("lang", "C")
    return "", 204


@app.route("/proxy", methods=["POST"])
def set_proxy():
    proxy = request.json["proxy"]
    name = request.args.get("var", "HTTP_PROXY")
~>    os.environ[name] = proxy
~>    os.putenv("HTTPS_PROXY", proxy)
    return "", 204


@app.route("/plugins")
def add_plugin_dir():
    plugin_dir = request.args["dir"]
~>    sys.path.insert(0, plugin_dir)
    return "ok"
