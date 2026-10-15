import hashlib
import hmac

from flask import abort, request


def handle_push(secret: bytes):
    signature = request.headers.get("X-Hub-Signature-256")
    expected = "sha256=" + hmac.new(secret, request.data, hashlib.sha256).hexdigest()
~>    if signature and not hmac.compare_digest(signature, expected):
        abort(401)
    return process(request.json)


def handle_upload(blob: bytes, checksum):
    actual = hashlib.sha256(blob).hexdigest()
~>    if checksum and actual != checksum:
        raise ValueError("corrupt upload")
    store(blob)
