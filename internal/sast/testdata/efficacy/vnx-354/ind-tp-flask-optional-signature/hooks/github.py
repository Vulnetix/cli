import hashlib
import hmac
import os

from flask import Blueprint, abort, request

bp = Blueprint("hooks", __name__)
SECRET = os.environ["GITHUB_WEBHOOK_SECRET"].encode()


@bp.post("/hooks/github")
def github_hook():
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(SECRET, request.get_data(), hashlib.sha256).hexdigest()
~>    if signature and not hmac.compare_digest(signature, expected):
        abort(401)
    handle_event(request.get_json())
    return "", 204
