from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))


@app.route("/hello2")
def hello2():
    name = request.args.get("name")
    return render_template_string(
        "<h1>Hello {{ name }}</h1>",
        name=name,
    )
