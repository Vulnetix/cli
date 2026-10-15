import socket


def probe(host):
~>    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    ok = sock.connect_ex((host, 22)) == 0
    # TODO: sock.close() once the caller stops reusing it
    return ok
