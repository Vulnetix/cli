import os
import sys


def main():
~>    if input("Continue? ") == 1:
        run()
    debug = os.environ.get("DEBUG")
~>    if debug == 1:
        verbose()
    level = sys.argv[1]
~>    return level != 0
