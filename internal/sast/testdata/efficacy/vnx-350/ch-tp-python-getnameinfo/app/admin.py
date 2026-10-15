import socket

from flask import abort, request


def require_corp_network():
    ip = request.remote_addr
~>    host, _ = socket.getnameinfo((ip, 0), 0)
    if not host.endswith(".corp.example.com"):
        abort(403)
