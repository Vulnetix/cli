import marshal
import pickle
import socket


def serve(port):
    srv = socket.socket()
    srv.bind(("0.0.0.0", port))
    srv.listen()
    conn, _ = srv.accept()
    data = conn.recv(65536)
~>    task = pickle.loads(data)
~>    code = marshal.loads(conn.recv(4096))
    return task, code
