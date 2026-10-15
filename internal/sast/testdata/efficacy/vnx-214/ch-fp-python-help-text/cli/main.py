import argparse
import logging

log = logging.getLogger(__name__)


def build_parser(prog):
    p = argparse.ArgumentParser(prog=prog, epilog="example: %s --token TOKEN" % prog)
    p.add_argument("--token", help="API token (or set APP_TOKEN)")
    return p


def warn(name):
    log.warning("flag --token for %s is deprecated, use APP_TOKEN", name)
