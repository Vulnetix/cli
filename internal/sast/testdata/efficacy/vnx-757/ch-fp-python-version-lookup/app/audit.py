import ssl

_PROTOCOL_NAMES = {
    ssl.PROTOCOL_TLSv1: "TLS 1.0",
    @@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][1]@@: "TLS 1.1",
    ssl.PROTOCOL_TLS_CLIENT: "negotiated",
}


def audit(ctx: ssl.SSLContext) -> str:
    if ctx.protocol == ssl.PROTOCOL_TLSv1 or ctx.protocol in (@@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][1]@@,):
        raise ValueError("legacy protocol configured")
    return _PROTOCOL_NAMES.get(ctx.protocol, "unknown")
