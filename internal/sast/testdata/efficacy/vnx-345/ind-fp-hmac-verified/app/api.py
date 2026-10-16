import base64
import hashlib
import hmac
import marshal

from flask import Flask, abort, request

app = Flask(__name__)
SECRET = b"loaded-from-env"


@app.route("/jobs", methods=["POST"])
def submit_job():
    raw = base64.b64decode(request.form["blob"])
    sig = request.headers.get("X-Signature", "")
    expected = hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        abort(403)
    code = marshal.loads(raw)
    return str(code.co_name)
