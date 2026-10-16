from flask import Flask
from jinja2 import Template

app = Flask(__name__)


@app.route("/card/<content>")
def card(content):
~>    return Template(f"<div>{content}</div>").render()
