from OpenSSL import SSL
from OpenSSL.SSL import SSLv3_METHOD


def make_context():
~>    ctx = SSL.Context(SSL.TLSv1_METHOD)
    ctx.use_certificate_file("server.pem")
    return ctx


def make_old():
~>    return SSL.Context(SSLv3_METHOD)


def make_v2():
~>    return SSL.Context(SSL.SSLv2_METHOD)
