import os
import sys
from pathlib import Path


def self_update(new_source):
~>    with open(__file__, "w") as fh:
        fh.write(new_source)


def append_marker(marker):
~>    with open(
        __file__ , mode='a', encoding="utf-8"
    ) as fh:
        fh.write(marker)


def replace_runner(payload):
~>    Path(__file__).write_text(payload)
~>    fd = os.open(sys.argv[0], os.O_WRONLY | os.O_TRUNC)
    os.write(fd, payload.encode())
