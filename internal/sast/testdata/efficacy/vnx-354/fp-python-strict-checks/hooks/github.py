import hashlib
import hmac

from flask import abort, request


def handle_push(secret: bytes):
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        abort(401)
    expected = "sha256=" + hmac.new(secret, request.data, hashlib.sha256).hexdigest()
    if signature and not hmac.compare_digest(signature, expected):
        abort(401)
    if not signature.startswith("sha256="):
        abort(400)
    return process(request.json)


def handle_upload(blob: bytes, checksum):
    actual = hashlib.sha256(blob).hexdigest()
    if checksum and hmac.compare_digest(actual, checksum):
        return store(blob)
    raise ValueError("corrupt upload")


def seen(blob, known_hashes):
    digest = hashlib.sha256(blob).hexdigest()
    return digest in known_hashes
