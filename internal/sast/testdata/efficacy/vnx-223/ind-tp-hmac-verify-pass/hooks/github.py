import hashlib
import hmac

from flask import Flask, request

app = Flask(__name__)
WEBHOOK_SECRET = b"from-vault"


@app.post("/hooks/github")
def github_hook():
    sig = request.headers.get("X-Hub-Signature-256", "")
    trusted = False
    try:
        expected = "sha256=" + hmac.new(WEBHOOK_SECRET, request.data, hashlib.sha256).hexdigest()
        trusted = hmac.compare_digest(expected, sig)
~>    except Exception:
        pass
    return process(request.get_json(), trusted=trusted)
