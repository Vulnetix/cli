import hashlib
import hmac


def handle(headers, body):
    sig = headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return 400
    expected = "sha256=" + hmac.new(KEY, body, hashlib.sha256).hexdigest()
    if sig and hmac.compare_digest(sig, expected):
        return accept(body)
    return 401
