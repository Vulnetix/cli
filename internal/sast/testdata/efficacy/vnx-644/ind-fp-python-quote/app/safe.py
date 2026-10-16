from urllib.parse import quote
from flask import request, make_response

def dl():
    resp = make_response(data())
    resp.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(request.args["file"])
    resp.headers["X-Mode"] = "static"
    return resp
