import socket

from flask import abort, request


def require_internal():
~>    host = socket.gethostbyaddr(request.remote_addr)[0]
    if not host.endswith(".corp.acme.com"):
        abort(403)
