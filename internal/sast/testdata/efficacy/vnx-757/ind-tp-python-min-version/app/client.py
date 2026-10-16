import ssl


def build():
    ctx = ssl.create_default_context()
~>    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx
