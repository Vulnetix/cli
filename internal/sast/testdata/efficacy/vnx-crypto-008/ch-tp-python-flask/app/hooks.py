import hashlib
import hmac

from flask import abort, request


def check(secret):
    expected_sig = hmac.new(secret, request.data, hashlib.sha256).hexdigest()
~>    if request.headers.get("X-Hub-Signature-256", "") != "sha256=" + expected_sig:
        abort(401)


def check_key(settings):
~>    if request.headers.get("X-Api-Key") == settings.API_KEY:
        return True
