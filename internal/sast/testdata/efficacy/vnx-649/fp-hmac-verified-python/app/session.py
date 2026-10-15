import base64
import hashlib
import hmac
import json

from flask import request, abort


def read():
    payload, sig = request.cookies["s"].rsplit(".", 1)
    expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(400)
    return json.loads(@@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(payload))
