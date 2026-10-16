import os
from pathlib import Path

def prepare(base):
~>    os.makedirs(base, 755)
~>    Path(base, "run").mkdir(mode=700)
    os.makedirs(base + "/ok", 0o755)
