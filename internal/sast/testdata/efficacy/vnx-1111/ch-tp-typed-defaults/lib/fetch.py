from typing import Dict, Optional, Tuple


~>async def fetch(url: str, headers: Optional[Dict[str, str]] = None, timeout: Tuple[float, float] = (3.0, 10.0), sep=", "):
    '''Fetch a URL.

    Args:
        url: absolute URL to request.
        headers: extra request headers.

    Raises:
        TimeoutError: when the server does not answer.
    '''
    return url, headers, timeout, sep
