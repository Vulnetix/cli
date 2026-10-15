import base64

PUBKEY = base64.b64decode("bm90LWEtc2VjcmV0")


def unpack(blob):
    return base64.b64decode(blob, validate=True)
