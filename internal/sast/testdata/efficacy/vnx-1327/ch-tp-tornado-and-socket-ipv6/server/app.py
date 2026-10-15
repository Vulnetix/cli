import socket
import tornado.ioloop
import tornado.web


def main(port):
    app = tornado.web.Application([])
~>    app.listen(8888, address="0.0.0.0")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
~>    sock.bind(("::", port))
    tornado.ioloop.IOLoop.current().start()
