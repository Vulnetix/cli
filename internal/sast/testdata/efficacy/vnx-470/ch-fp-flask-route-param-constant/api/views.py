from flask import Flask, jsonify

from . import handlers

app = Flask(__name__)


@app.route("/items/<item_id>")
def item(item_id):
    fn = getattr(handlers, "show_item")
    return jsonify(fn(item_id))


def other(name):
    return getattr(handlers, name)
