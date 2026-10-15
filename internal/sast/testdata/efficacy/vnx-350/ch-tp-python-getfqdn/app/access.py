import socket

from flask import abort, request


def internal_only():
~>    host = socket.getfqdn(request.remote_addr)
    if not host.endswith(".corp.example.com"):
        abort(403)
