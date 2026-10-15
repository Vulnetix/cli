from pathlib import Path

from flask import Flask, render_template_string, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment(autoescape=True)
SRC = Path("templates/report.html").read_text()


@app.route("/report")
def report():
    tpl = env.from_string(SRC)
    return tpl.render(month=request.args.get("month"))


@app.route("/legal")
def legal():
    text = Path("templates/legal.html").read_text()
    return render_template_string(text, lang=request.args.get("lang", "en"))
