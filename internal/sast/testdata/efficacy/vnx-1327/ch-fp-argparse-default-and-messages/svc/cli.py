import argparse
import logging

log = logging.getLogger(__name__)


def parse():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0", help="address to bind, e.g. 0.0.0.0")
    return p.parse_args()


def describe(addr):
    if addr == "0.0.0.0":
        log.warning("binding to 0.0.0.0 exposes the service on every interface")
    return "listening on %s" % addr


def main():
    args = parse()
    print(describe(args.host))
