import ssl
import socket
from OpenSSL import SSL


def legacy_socket(host):
~>    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)


def wrapped(sock):
~>    return ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3)


def lowered():
    ctx = ssl.create_default_context()
~>    ctx.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1]@@
~>    ctx.options &= ~ssl.OP_NO_TLSv1_1
~>    ctx.set_ciphers("ECDHE+AESGCM:RC4-SHA:!aNULL")
    return ctx


def openssl_ctx():
~>    return SSL.Context(SSL.TLSv1_1_METHOD)


def everything():
    ctx = ssl.create_default_context()
~>    ctx.set_ciphers('ALL:@SECLEVEL=0')
~>    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    return ctx
