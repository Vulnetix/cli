from flask import Flask, request, render_template_string
from jinja2 import Environment, Template

app = Flask(__name__)
env = Environment()


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    page = "<h1>Hello " + name + "</h1>"
~>    return render_template_string(page)


@app.route("/preview", methods=["POST"])
def preview():
~>    tpl = env.from_string(request.form["body"])
~>    other = Template(request.json.get("tpl"))
    return tpl.render() + other.render()


@app.route("/greet")
def greet():
~>    return render_template_string(f"<p>Hi {request.args['who']}</p>")
