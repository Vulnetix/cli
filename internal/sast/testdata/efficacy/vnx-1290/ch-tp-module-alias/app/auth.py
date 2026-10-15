import base64 as b64
import json

from starlette.requests import Request


async def current_user(request: Request):
    cookie = request.cookies.get("uid")
~>    ident = json.loads(@@sample:b[6]4[.][u]rl[s]af[e][_]b[6]4d[e]co[d]e@@(cookie))
    return ident["user_id"]
