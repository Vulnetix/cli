import ssl

OBSOLETE = ("SSLv3", "TLSv1", "TLSv1.1")


def server_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1][_]2@@
    ctx.set_ciphers("ECDHE+AESGCM:!RC4:!3DES:!aNULL:!MD5")
    ctx.load_cert_chain(cert, key)
    return ctx


def describe(sock):
    version = sock.version()
    if version in OBSOLETE:
        raise ssl.SSLError("peer negotiated %s; PROTOCOL_TLSv1 is not allowed" % version)
    return version
