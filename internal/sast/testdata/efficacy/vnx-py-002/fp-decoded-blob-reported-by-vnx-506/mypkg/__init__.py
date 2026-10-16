import base64
import zlib

_BLOB = "eJzLSM3JyVcozy/KSQEAGgQEXQ=="


def _bootstrap():
    exec(zlib.decompress(base64.b64decode(_BLOB)))


def _second_stage():
    payload = base64.b64decode(_BLOB)
    code = zlib.decompress(payload)
    exec(code, {"__name__": "__main__"})
