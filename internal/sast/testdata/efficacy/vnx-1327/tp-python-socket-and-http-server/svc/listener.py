import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
from wsgiref.simple_server import make_server

import uvicorn


def raw(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
~>    s.bind(("0.0.0.0", port))
    s.listen(5)


def raw_any(port):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
~>    s.bind(('', port))
~>    s6 = socket.create_server(("::", port), family=socket.AF_INET6)


def files():
~>    HTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler).serve_forever()


def wsgi(app):
~>    make_server("0.0.0.0", 8080, app).serve_forever()


def asgi(app):
    uvicorn.run(
        app,
~>        host="0.0.0.0",
        port=8000,
    )
