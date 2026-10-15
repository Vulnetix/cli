import httpx


~>def fetch_upstream(url: str, *, verify_ssl: bool = False, timeout: float = 10.0) -> bytes:
    with httpx.Client(verify=verify_ssl, timeout=timeout) as client:
        return client.get(url).content
