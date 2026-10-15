import hashlib

# if signature and not hmac.compare_digest(signature, expected): would be a bug
HELP = "if sig and sig != expected: skips the check"


def file_id(path):
    digest = hashlib.sha1(path.encode()).hexdigest()
    return digest[:10]


def is_hex(value):
    return value.startswith("0x")
