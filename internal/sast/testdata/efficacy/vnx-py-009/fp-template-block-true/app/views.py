from flask import Flask, render_template

app = Flask(__name__)


@app.route("/p")
def page():
    return render_template("page.html", page=load())
