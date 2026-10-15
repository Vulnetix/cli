import os
import sys


def main(args):
    """Do not do os.chroot(request.args['root'])."""
    # sys.path.insert(0, request.args["dir"])
    root = sys.argv[1]
    os.chroot(root)
