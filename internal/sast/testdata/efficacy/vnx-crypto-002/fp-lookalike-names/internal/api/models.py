import hashlib


class Commit:
    def sha1(self):
        return self._oid

    def short(self):
        return self.sha1()[:7]


def lookup_sha1(row):
    return row["sha1"]


def safe(data):
    return hashlib.sha256(data).hexdigest()
