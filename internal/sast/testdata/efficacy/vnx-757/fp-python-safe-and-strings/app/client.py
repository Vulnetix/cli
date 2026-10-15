import ssl
from OpenSSL import SSL

LEGACY = {"TLSv1": 0x0301, "TLSv1.1": 0x0302}


def modern():
    # ssl.PROTOCOL_TLSv1 is deprecated, use PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1][_]2@@
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!eNULL:!MD5:!RC4:!DES")
    print("ssl.PROTOCOL_SSLv3 is not supported")
    return ctx


def pinned():
    return ssl.SSLContext(@@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][2]@@)


def openssl_ctx():
    return SSL.Context(SSL.TLS_METHOD)
