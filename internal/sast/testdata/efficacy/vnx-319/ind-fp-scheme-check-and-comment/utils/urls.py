# Legacy docs used http://docs.vendor-platform.com/api, now served over TLS.


def enforce_tls(url: str) -> str:
    if url.startswith("http://"):
        raise ValueError("cleartext URLs are not allowed")
    return url
