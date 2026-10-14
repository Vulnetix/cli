import os
import tempfile


def name():
~>    target = tempfile.mktemp(
        suffix=".tar",
        dir=os.environ.get("TMPDIR"),
    )
    return target


def old_style():
~>    return os.tempnam("/var/tmp", "app")


def older_style():
~>    return os.tmpnam()
