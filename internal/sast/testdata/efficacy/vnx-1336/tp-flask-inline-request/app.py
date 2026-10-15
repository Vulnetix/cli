import flask
from flask import request

app = flask.Flask(__name__)


@app.post("/preview")
def preview():
~>    return flask.render_template_string(request.form['tpl'])


@app.get("/greet")
def greet():
~>    return flask.render_template_string("Hi " + request.args.get("who", ""))
