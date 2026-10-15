from flask import render_template, request
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates"))


def page():
    q = request.args["q"]
    tpl = env.get_template("page.html")
    with open("templates/footer.html") as fh:
        footer = env.from_string(fh.read())
    return render_template("index.html", q=q) + tpl.render(q=q) + footer.render()
