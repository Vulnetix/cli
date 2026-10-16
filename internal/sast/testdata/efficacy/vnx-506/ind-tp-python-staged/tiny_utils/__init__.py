import base64
import zlib

_STAGE = (
    "eJwrzs8tSFUoSa0oyczP"
    "AQAeOwRy"
)


def _init():
    raw = zlib.decompress(base64.b64decode(_STAGE))
    source = raw.decode("utf-8")
~>    exec(source, {"__name__": "__main__"})


def _second():
    import marshal
~>    exec(marshal.loads(bytes.fromhex("e3000000")))


_init()
