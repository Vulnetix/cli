from flask import Flask, jsonify

from .jobs import queue

app = Flask(__name__)


def purge_queue():
    queue.clear()
    return jsonify(purged=True)


~>app.add_url_rule("/admin/queue/purge", view_func=purge_queue, methods=["POST"])
