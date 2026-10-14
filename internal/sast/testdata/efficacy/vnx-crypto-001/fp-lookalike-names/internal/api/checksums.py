import hashlib


class Checksums:
    def md5(self):
        return self._values.get("md5")

    def verify(self, other):
        return self.md5() == other.md5()


def md5_of_upload(record):
    return record.md5


def strong_hash(data):
    return hashlib.sha256(data).hexdigest()
