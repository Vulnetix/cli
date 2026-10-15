import os
import tempfile


def stage(workdir):
~>    target = tempfile.mktemp(prefix="stage-", dir=workdir)
    os.rename(os.path.join(workdir, "out"), target)
    return target
