import os
import sys


def deploy(target):
    cmd = "rsync -a build/ %s" % sys.argv[1]
    os.system(cmd)
