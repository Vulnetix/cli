from OpenSSL import SSL


def server_context():
    ctx = SSL.Context(SSL.TLS_METHOD)
~>    ctx.set_min_proto_version(SSL.TLS1_VERSION)
    return ctx
