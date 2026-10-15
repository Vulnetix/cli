import base64
import json

from flask import request, abort


def profile():
~>    prefs = json.loads(base64.b64decode(request.cookies["profile"]))
    if not prefs.get("is_admin"):
        abort(403)
~>    ctx = json.loads(@@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(request.args.get("state", "")).decode())
    return render(prefs, ctx)
