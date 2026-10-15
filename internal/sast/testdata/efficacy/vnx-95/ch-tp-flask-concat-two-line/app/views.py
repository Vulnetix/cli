from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    page = "<h1>Hello " + request.args.get("name", "guest") + "</h1>"
~>    return render_template_string(page)


@app.route("/card")
def card():
    title = request.values.get("title")
    markup = f"<div class='card'>{title}</div>"
~>    return render_template_string(
        markup,
        footer="(c) Example",
    )
