import socket
from marshal import loads


def serve(port=9100):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        data = conn.recv(65536)
~>        task = loads(data)
        conn.sendall(repr(task.co_names).encode())
        conn.close()
