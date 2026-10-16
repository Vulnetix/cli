import ssl


def make_context():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!RC4:!aNULL:!eNULL:!MD5")
    return ctx


# PROTOCOL_TLSv1 was removed from our code base in 2021.
VERSIONS = {"tlsv1": "TLS 1.0", "tlsv1_1": "TLS 1.1"}
