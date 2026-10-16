import socket


def forward_raw(backend_host, body: bytes):
~>    head = b"POST /api/jobs HTTP/1.1\r\nHost: backend\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
    with socket.create_connection((backend_host, 80)) as s:
        s.sendall(head + body)
        return s.recv(4096)
