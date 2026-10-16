import hashlib
import hmac
import os

from flask import Flask, abort, request

app = Flask(__name__)
WEBHOOK_KEY = os.environ["GITHUB_WEBHOOK_KEY"].encode()


@app.route("/webhooks/github", methods=["POST"])
def github_webhook():
    signature = request.headers.get("X-Hub-Signature-256")
    if signature is None:
        abort(400)
    expected = "sha256=" + hmac.new(WEBHOOK_KEY, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(401)
    return "", 204
