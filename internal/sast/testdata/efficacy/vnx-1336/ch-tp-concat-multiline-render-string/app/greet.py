from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
~>    return render_template_string(
        "<h1>Hello " + request.args.get("name", "") + "</h1>"
    )
