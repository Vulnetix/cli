import os
import site
import sys

~>sys.path.append(".")
~>sys.path.insert(0, os.getcwd())
~>site.addsitedir("vendor")

import releaselib  # noqa: E402


def main():
    releaselib.run(sys.argv[1:])
