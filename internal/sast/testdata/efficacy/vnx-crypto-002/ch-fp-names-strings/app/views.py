SHA1_HEADER = "X-Content-SHA1"
message = "hashlib.sha1() is deprecated for signatures"


def get_sha1(row):
    return row["sha1"]
