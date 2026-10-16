import os
import pdb


def handle(args, request):
    if args.pdb:
        pdb.set_trace()
    if os.environ.get("DEBUG"):
        breakpoint()
    return request
