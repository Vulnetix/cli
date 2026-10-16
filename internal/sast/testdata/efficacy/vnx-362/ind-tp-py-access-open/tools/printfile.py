#!/usr/bin/env python3
# Installed setuid so operators can print spool files they own.
import os
import sys


def main(argv):
    target = argv[1]
    if not os.access(target, os.R_OK):
        print("permission denied", file=sys.stderr)
        return 2
~>    with open(target, "rb") as src:
        sys.stdout.buffer.write(src.read())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
