from flask import Flask, jsonify, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment(autoescape=True)


@app.post("/notify/preview")
def notify_preview():
    body = request.get_json()["template"]
~>    rendered = env.from_string(body).render(user="alice")
    return jsonify(text=rendered)
