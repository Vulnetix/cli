import base64
import json

from flask import request


def caller():
    token = request.headers.get("X-User-Token")
~>    claims = json.loads(@@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(token + "=="))
~>    role = bytes.fromhex(request.headers["X-Session-Id"]).decode()
    return claims["sub"], role
