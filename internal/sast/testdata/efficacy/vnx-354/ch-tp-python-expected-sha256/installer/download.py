import hashlib
import urllib.request


def fetch(url, dest, expected_sha256=None):
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    actual = hashlib.sha256(data).hexdigest()
~>    if expected_sha256 and actual != expected_sha256:
        raise ValueError("sha256 mismatch for %s" % url)
    with open(dest, "wb") as fh:
        fh.write(data)


def fetch_legacy(url, dest, md5=None):
    data = urllib.request.urlopen(url).read()
~>    if md5 and hashlib.md5(data).hexdigest() != md5:
        raise ValueError("md5 mismatch")
    open(dest, "wb").write(data)
