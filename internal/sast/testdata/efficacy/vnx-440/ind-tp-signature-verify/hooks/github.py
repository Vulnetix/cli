import hashlib
import hmac

from flask import request


def receive():
    body = request.get_data()
    expected = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    sent = request.headers.get("X-Hub-Signature-256", "")
~>    assert hmac.compare_digest(sent, expected), "bad signature"
    return handle_event(request.get_json())


def receive_stripe(payload, header):
~>    assert verify_stripe_signature(payload, header, STRIPE_SECRET)
    return process(payload)
