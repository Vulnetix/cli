import ssl

# ssl.PROTOCOL_TLSv1 and SSLv3_METHOD are rejected by modern servers.
REJECTED = ["PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "TLSv1_METHOD"]


def has_legacy():
    return hasattr(ssl, "PROTOCOL_TLSv1")
