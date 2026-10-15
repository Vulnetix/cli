import hashlib
import hmac

from flask import request

from .config import settings


def receive():
    body = request.get_data()
    expected = hmac.new(settings.SECRET, body, hashlib.sha256).hexdigest()
    received = request.headers.get("X-Signature", "")
~>    assert hmac.compare_digest(received, expected), "bad signature"
    return handle(body)


def internal_call():
    supplied = request.headers.get("Authorization", "")
~>    assert supplied == settings.API_TOKEN
    return run_job()
