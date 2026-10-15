import os
import sys


def show(filename):
    if os.access(filename, os.R_OK):
~>        print(open(filename).read())
    else:
        sys.exit("permission denied")
