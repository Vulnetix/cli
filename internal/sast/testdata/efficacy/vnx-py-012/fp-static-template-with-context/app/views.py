from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)
CARD = "<p>{{ msg }}</p>"


@app.route("/x")
def x():
    name = request.args.get("name")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


@app.route("/y")
def y():
    return render_template("hello.html", name=request.args.get("name"))


@app.route("/z")
def z():
    return render_template_string(CARD, msg=request.args.get("m"))


@app.route("/w")
def w():
    layout = load_layout("default")
    return render_template_string(layout, user=request.args.get("u"))


@app.route("/v")
def v():
    header = "<h1>{{ title }}</h1>"
    return render_template_string(header + FOOTER, title=request.args.get("t"))
