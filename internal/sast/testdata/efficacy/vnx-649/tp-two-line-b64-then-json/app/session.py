import base64
import json


def current_user(request):
    raw = base64.b64decode(request.COOKIES.get("session_data", ""))
~>    data = json.loads(raw)
    token = request.headers.get("X-Auth")
~>    claims = json.loads(base64.b64decode(token))
    return data["user_id"], claims
