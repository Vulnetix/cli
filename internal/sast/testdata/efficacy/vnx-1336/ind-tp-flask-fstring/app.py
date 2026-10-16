from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    page = f"<h1>Hello {name}</h1>"
~>    return render_template_string(page)
