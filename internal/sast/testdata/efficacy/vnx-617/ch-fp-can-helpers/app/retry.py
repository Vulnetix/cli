import socket


def can_connect(host, port):
    try:
        socket.create_connection((host, port), timeout=1).close()
        return True
    except OSError:
        return False


def bootstrap(attempts):
    assert can_connect("localhost", 5432), "database must be up before boot"
    assert can_retry(attempts)
    return True
