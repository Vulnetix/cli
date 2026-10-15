import ssl

from OpenSSL import SSL


def contexts():
    a = ssl.SSLContext(@@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][2]@@)
    a.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1][_]2@@
    a.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    b = SSL.Context(SSL.TLSv1_2_METHOD)
    b.set_min_proto_version(SSL.TLS1_2_VERSION)
    return a, b
