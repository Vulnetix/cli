from string import Template

from flask import Flask, request

app = Flask(__name__)


@app.route("/label")
def label():
    # string.Template only substitutes $names; it cannot run code.
    fmt = request.args.get("fmt", "$user")
    return Template(fmt).safe_substitute(user="alice")
