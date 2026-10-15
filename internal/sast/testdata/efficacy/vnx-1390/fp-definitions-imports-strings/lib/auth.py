from requests.auth import HTTPDigestAuth
import requests_ntlm


class HTTPDigestAuth(AuthBase):
    """Attaches HTTP Digest Authentication to the given Request object.

    >>> requests.get(url, auth=HTTPDigestAuth("user", "pass"))
    """

    def __init__(self, username, password):
        self.username = username


# auth = HTTPDigestAuth(user, pw)  -- old client, removed
SCHEMES = ["NTLM", "Digest"]
HELP = "use HttpNtlmAuth(user, pw) only for legacy shares"
