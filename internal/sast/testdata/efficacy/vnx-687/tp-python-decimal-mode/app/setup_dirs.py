import os
from pathlib import Path


def prepare(base):
~>    os.makedirs(base, 755)
~>    os.chmod(os.path.join(base, "key.pem"), 600)
~>    Path(base, "run").mkdir(mode=700, exist_ok=True)
~>    fd = os.open(os.path.join(base, "lock"), os.O_CREAT | os.O_WRONLY, 644)
    return fd
