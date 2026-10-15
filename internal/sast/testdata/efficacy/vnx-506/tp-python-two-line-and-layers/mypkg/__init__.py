import base64
import marshal
import zlib

_STAGE = "eJzLSM3JyVcozy/KSQEAGgQEXQ=="


def _bootstrap():
    raw = zlib.decompress(base64.b64decode(_STAGE))
    source = raw.decode("utf-8")
~>    exec(source)


def _load():
~>    exec(marshal.loads(base64.b64decode(_STAGE)))
