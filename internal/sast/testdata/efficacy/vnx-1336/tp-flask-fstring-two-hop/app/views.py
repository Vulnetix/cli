from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    template = f"<h1>Hello {name}</h1>"
~>    return render_template_string(template)


@app.route("/card")
def card():
    title = request.form["title"]
    body = "<div class='card'>" + title + "</div>"
~>    return render_template_string(
        body
    )
