import os
import sys


def daemonize(workdir="/"):
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    os.chdir(workdir)
~>    os.umask(0)
    sys.stdout.flush()
    sys.stderr.flush()
