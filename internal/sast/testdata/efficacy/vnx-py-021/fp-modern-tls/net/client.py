import ssl

from OpenSSL import SSL


def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    negotiated = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    pinned = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    return ctx, server, negotiated, pinned


def pyopenssl():
    a = SSL.Context(SSL.TLS_METHOD)
    b = SSL.Context(SSL.SSLv23_METHOD)
    c = SSL.Context(SSL.TLSv1_2_METHOD)
    return a, b, c
