import ssl


def make_context():
~>    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.load_cert_chain("server.pem")
    return ctx


def legacy_ciphers(ctx):
~>    ctx.set_ciphers("AES128-SHA:RC4-SHA")
