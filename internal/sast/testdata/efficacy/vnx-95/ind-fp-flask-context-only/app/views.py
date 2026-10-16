from flask import Flask, render_template, render_template_string, request

app = Flask(__name__)

GREETING = "<h1>Hello {{ name }}</h1><p>{{ note }}</p>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string(GREETING, name=name, note=request.args.get("note"))


@app.route("/profile")
def profile():
    return render_template("profile.html", user=request.args.get("user"))
