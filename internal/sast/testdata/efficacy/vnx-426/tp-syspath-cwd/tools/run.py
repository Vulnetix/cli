import os
import sys
from pathlib import Path

~>sys.path.insert(0, "")
~>sys.path.insert(0, '.')
~>sys.path.append("lib")
~>sys.path.append(os.getcwd())
~>sys.path.insert(1, os.path.abspath(".."))
~>sys.path.extend(["./vendor", "/opt/app/lib"])
~>sys.path.append(str(Path.cwd()))

import plugins  # noqa: E402
