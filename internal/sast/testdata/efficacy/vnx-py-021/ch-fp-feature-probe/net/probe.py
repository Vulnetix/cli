import ssl

LEGACY = [name for name in ("PROTOCOL_SSLv3", "PROTOCOL_TLSv1") if hasattr(ssl, name)]


def check(ctx):
    if ctx.minimum_version <= @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1][_]1@@:
        raise ValueError("TLS 1.1 and below are not allowed")
