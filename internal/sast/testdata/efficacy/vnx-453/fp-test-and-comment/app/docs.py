# Never write def fetch(url, verify=False): callers inherit the insecure default.
EXAMPLE = "def fetch(url, verify=False):"


def fetch(url, verify=True):
    """Fetch a URL.

    def fetch(url, verify=False) was the old, insecure signature.
    """
    return url
