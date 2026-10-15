from flask import Flask, request, render_template, render_template_string

app = Flask(__name__)

PAGE = "<h1>Hello {{ name }}</h1>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string(PAGE, name=name)


@app.route("/profile")
def profile():
    return render_template("profile.html", bio=request.form.get("bio"))


@app.route("/inline")
def inline():
    q = request.args.get("q")
    return render_template_string("<p>{{ q }}</p>", q=q)
