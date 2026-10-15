from flask import Flask, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
env = SandboxedEnvironment()


@app.route("/custom", methods=["POST"])
def custom():
    return env.from_string(request.form["template"]).render()
