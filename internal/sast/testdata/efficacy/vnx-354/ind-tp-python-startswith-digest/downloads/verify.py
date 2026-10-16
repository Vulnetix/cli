import hashlib


def verify_download(path, provided_checksum):
    with open(path, "rb") as fh:
        computed = hashlib.sha256(fh.read()).hexdigest()
~>    if not computed.startswith(provided_checksum.lower()):
        raise ValueError("checksum mismatch")
    return path
