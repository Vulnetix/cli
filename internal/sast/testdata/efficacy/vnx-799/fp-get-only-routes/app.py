from flask import Flask, render_template

app = Flask(__name__)


@app.route("/login")
def login_form():
    return render_template("login.html")
