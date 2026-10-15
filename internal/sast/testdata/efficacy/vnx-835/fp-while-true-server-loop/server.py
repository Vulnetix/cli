import socket


def serve(sock):
    while True:
        conn, _ = sock.accept()
        handle(conn)
