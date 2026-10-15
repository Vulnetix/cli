import logging


def main(args):
    if args.quiet:
        logging.disable(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.disable(logging.NOTSET)
    noisy = logging.getLogger("chardet")
    noisy.propagate = False
