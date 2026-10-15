import socket


def is_internal(request):
~>    host = socket.gethostbyaddr(request.remote_addr)[0]
    if host.endswith(".corp.example.com"):
        return True
    return False


def admin_allowed(ip):
~>    name, _aliases, _addrs = socket.gethostbyaddr(ip)
    return name in ALLOWED_HOSTS
