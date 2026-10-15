from flask import Flask, render_template_string, request

app = Flask(__name__)

PAGE = "<p>Results for {{ q }}</p>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(PAGE, q=q)


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))
