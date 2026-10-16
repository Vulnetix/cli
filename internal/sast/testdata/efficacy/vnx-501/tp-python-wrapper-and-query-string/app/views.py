import flask
from flask import request
import app.support


def save_wrapped():
    reader = app.support.Reader(request)
    label = reader.form("label")
~>    flask.session[label] = '1'


def save_from_query():
    qs = request.query_string.decode('utf-8')
    pos = qs.find('theme=')
    theme = qs[pos + 6:]
~>    flask.session['theme'] = theme


def save_after_substring_test():
    label = "This should never happen"
    if 'should' in label:
        label = request.form.get("label")
~>    flask.session[label] = '1'
