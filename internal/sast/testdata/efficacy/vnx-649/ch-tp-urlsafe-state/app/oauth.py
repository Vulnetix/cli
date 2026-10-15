import base64
import json
from flask import request, redirect


def callback():
    raw = @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(request.args["state"])
~>    state = json.loads(raw)
    return redirect(state["next"])
