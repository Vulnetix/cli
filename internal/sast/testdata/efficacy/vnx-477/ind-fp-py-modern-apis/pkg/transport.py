import importlib
import logging
import socket
import ssl
import time
import warnings
from collections.abc import Mapping

log = logging.getLogger(__name__)


def connect(host, port, opts):
    if not isinstance(opts, Mapping):
        warnings.warn("opts should be a mapping", DeprecationWarning, stacklevel=2)
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port))
    start = time.perf_counter()
    tls = ctx.wrap_socket(sock, server_hostname=host)
    log.warning("handshake took %.3fs", time.perf_counter() - start)
    return tls, importlib.import_module("json")
