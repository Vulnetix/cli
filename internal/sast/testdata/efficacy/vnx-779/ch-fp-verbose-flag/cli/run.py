import logging
import os


def main(args):
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    logging.info("home is %s", os.environ.get("HOME"))
