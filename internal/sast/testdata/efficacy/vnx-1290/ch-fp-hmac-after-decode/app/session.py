import base64
import hashlib
import hmac

from flask import request, abort, current_app


def read_session():
    blob = request.cookies.get("session")
    raw = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(blob)
    payload, sig = raw.rsplit(b".", 1)
    expected = hmac.new(current_app.secret_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        abort(401)
    return payload
