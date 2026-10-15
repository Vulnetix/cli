import base64
import collections
import inspect
import logging
import platform
import socket
import ssl
import time


def connect(host):
    sock = socket.create_connection((host, 443))
~>    return ssl.wrap_socket(sock, ssl_version=@@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][2]@@)


def describe():
~>    name = platform.linux_distribution()[0]
~>    blob = base64.encodestring(name.encode())
~>    logging.warn("distro %s", name)
~>    start = time.clock()
    return blob, start


def is_map(x):
~>    return isinstance(x, collections.Mapping)


def params(fn):
~>    return inspect.getargspec(fn).args
