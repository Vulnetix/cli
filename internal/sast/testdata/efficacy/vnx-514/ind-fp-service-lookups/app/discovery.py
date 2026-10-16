import socket

import dns.resolver


def endpoints(service: str, namespace: str):
    host = f"{service}.{namespace}.svc.cluster.local"
    addr = socket.gethostbyname(host)
    mx = dns.resolver.resolve("example.com", "MX")
    digest = "deadbeef".encode().hex()
    print(digest)
    return addr, mx, socket.getaddrinfo("db.internal", 5432)
