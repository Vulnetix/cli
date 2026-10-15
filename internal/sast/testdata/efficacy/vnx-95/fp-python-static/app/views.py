from string import Template as StrTemplate

from flask import Flask, request, render_template, render_template_string
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"))


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    page = render_template("hello.html", name=name)
    banner = render_template_string("<h1>{{ name }}</h1>", name=name)
    tpl = env.get_template("mail.txt").render(user=name)
    greeting = StrTemplate("Hello $who").substitute(who=request.args["who"])
    # render_template_string(request.args["t"]) is a bad idea
    note = "never call render_template_string(request.args['t'])"
    return page + banner + tpl + greeting + note
