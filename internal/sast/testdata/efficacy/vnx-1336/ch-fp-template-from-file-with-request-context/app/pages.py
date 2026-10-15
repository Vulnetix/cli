from flask import Flask, request, render_template, render_template_string

app = Flask(__name__)

with open("templates/page.html") as fh:
    PAGE = fh.read()


@app.route("/a")
def a():
    return render_template_string(PAGE, user=request.args.get("u"))


@app.route("/b")
def b():
    return render_template("page.html", q=request.args.get("q"))
