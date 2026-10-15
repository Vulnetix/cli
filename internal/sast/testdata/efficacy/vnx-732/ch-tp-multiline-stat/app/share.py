import os
import stat


def share(path):
~>    os.chmod(
        path,
        stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
    )
