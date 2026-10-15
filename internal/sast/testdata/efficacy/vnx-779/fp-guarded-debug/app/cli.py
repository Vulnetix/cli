import logging
import http.client


def main(args):
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)
    http.client.HTTPConnection.debuglevel = 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
