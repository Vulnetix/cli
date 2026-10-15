import jinja2
from flask import Flask, request

app = Flask(__name__)


@app.route("/preview", methods=["POST"])
def preview():
~>    return jinja2.Template(request.form["body"]).render()
