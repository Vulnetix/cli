from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    page = "<h1>Hello " + request.args.get("name", "guest") + "</h1>"
~>    return render_template_string(page)
