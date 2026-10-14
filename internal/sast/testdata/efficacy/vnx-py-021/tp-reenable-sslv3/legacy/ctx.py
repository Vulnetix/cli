import ssl


def permissive():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
~>    ctx.options &= ~ssl.OP_NO_SSLv3
~>    ctx.options &= ~ssl.OP_NO_TLSv1
    return ctx
