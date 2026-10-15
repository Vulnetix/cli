from flask import request


def proxy_hop():
~>    return request.headers["X-Forwarded-For"].rsplit(",", 2)[1].strip()
