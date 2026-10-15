import hashlib
import hmac

import requests
from requests.auth import HTTPBasicAuth
from requests_kerberos import HTTPKerberosAuth, OPTIONAL


def checksum(data):
    return hashlib.md5(data).hexdigest()


def same(a, b):
    return hmac.compare_digest(a, b)


def call(url):
    return requests.get(url, auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL))


def call_basic(url, u, p):
    return requests.get(url, auth=HTTPBasicAuth(u, p))

# HTTPDigestAuth(user, pw) was removed: digest is MD5-based
