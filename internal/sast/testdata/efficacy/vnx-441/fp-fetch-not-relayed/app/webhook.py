import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/ping", methods=["POST"])
def ping():
    url = request.json["callback"]
    upstream = requests.post(url, json={"ok": True}, timeout=5)
    log_status(upstream.status_code)
    return jsonify({"queued": True})


def log_status(code):
    print("callback status", code)
