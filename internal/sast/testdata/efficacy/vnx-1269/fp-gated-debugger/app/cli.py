import os
import pdb
import sys


def main(args):
    if args.pdb:
        pdb.set_trace()
    if os.environ.get("ENABLE_DEBUGPY"):
        import debugpy
        debugpy.listen(5678)
    try:
        run(args)
    except Exception:
        if args.debug:
            pdb.post_mortem()
        raise


def run(args):
    return sys.exit(0)
