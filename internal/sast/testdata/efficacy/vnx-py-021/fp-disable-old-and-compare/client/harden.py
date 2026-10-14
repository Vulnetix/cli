import ssl


def harden(ctx):
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ctx.protocol == ssl.PROTOCOL_TLSv1:
        raise ValueError("TLS 1.0 is not allowed")
    return ctx
