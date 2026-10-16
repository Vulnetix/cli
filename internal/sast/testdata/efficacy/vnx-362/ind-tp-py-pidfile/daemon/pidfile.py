import os
import sys


def acquire_pidfile(pidfile: str) -> None:
    """Write our pid so the init script can find us."""
    if os.path.exists(pidfile):
        sys.stderr.write("pidfile %s exists, is another instance running?\n" % pidfile)
        sys.exit(1)
~>    with open(pidfile, "w") as fh:
        fh.write(str(os.getpid()))
