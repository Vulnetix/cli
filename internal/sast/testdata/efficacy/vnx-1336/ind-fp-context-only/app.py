from flask import Flask, request, render_template_string, render_template
app = Flask(__name__)

@app.route("/hi")
def hi():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

@app.route("/p")
def p():
    return render_template("profile.html", name=request.args.get("name"))
