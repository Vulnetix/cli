import pdb
import sys


def main(args):
    if args.pdb: pdb.set_trace()
    try:
        return run(args)
    except Exception:
        if args.post_mortem:
            pdb.post_mortem(sys.exc_info()[2])
        raise


def run(args):
    return 0
