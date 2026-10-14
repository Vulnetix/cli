from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
~>    return render_template_string(request.args.get("tpl", "Hello"))


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    template = "<h1>Hello %s!</h1>" % name
~>    return render_template_string(template)


@app.route("/card", methods=["POST"])
def card():
    title = request.form["title"]
~>    return render_template_string(f"<div class='card'>{title}</div>")


@app.route("/footer")
def footer():
    note = request.values.get("note")
~>    return render_template_string("<footer>" + note + "</footer>")


@app.route("/user/<username>")
def profile(username):
    page = """
    <h2>Profile of {}</h2>
    """.format(username)
~>    return render_template_string(page)
