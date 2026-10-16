import logging

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("webhooks", __name__)
log = logging.getLogger(__name__)


@bp.route("/webhooks/test", methods=["POST"])
def test_webhook():
    callback = request.json.get("callback_url")
    resp = requests.post(callback, json={"event": "ping"}, timeout=3)
    log.info("webhook ping returned %s", resp.status_code)
    return jsonify({"delivered": resp.ok})
