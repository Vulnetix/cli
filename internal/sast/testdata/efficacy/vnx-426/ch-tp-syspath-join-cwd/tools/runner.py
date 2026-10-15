import os
import sys

~>sys.path.append(os.path.join(os.getcwd(), "plugins"))
~>sys.path.insert(0, os.path.join("vendor", "lib"))

import plugin_loader  # noqa: E402
