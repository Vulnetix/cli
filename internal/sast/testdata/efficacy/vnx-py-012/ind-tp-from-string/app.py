from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment(autoescape=True)


@app.route("/x", methods=["POST"])
def x():
~>    t = env.from_string(request.json["body"])
    return t.render()
