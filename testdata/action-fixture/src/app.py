import os
import sys


def run(cmd):
    # A command built from user input: the SAST rules flag this.
    os.system("ls " + sys.argv[1])
    return eval(cmd)
