import ipaddress

from flask import abort, request

INTERNAL_NET = ipaddress.ip_network("10.0.0.0/8")


def require_internal():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
~>    if ipaddress.ip_address(client_ip) not in INTERNAL_NET:
        abort(403)
