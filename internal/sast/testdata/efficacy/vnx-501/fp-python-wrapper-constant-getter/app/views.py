import flask
from flask import request
import app.support


def save_fixed():
    reader = app.support.Reader(request)
    label = reader.fixed("label")
    flask.session[label] = '1'
