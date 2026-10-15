import ipaddress

from flask import abort, request


def metrics():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
~>    if not ipaddress.ip_address(ip).is_private:
        abort(403)
    return render_metrics()
