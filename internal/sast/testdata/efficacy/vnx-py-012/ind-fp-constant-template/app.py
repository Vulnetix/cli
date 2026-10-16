from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


@app.route("/greet2")
def greet2():
    return render_template("greet.html", name=request.args.get("name"))
