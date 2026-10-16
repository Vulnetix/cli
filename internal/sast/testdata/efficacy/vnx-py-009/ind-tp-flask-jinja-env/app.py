from flask import Flask, render_template

app = Flask(__name__)
~>app.jinja_env.autoescape = False


@app.route("/")
def index():
    return render_template("index.html", title="Home")
