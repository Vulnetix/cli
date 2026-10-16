import argparse


def build_parser():
    parser = argparse.ArgumentParser(prog="mirror-sync")
    parser.add_argument("source")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--verify-ssl",
~>        type=bool,
        default=True,
        help="verify TLS certificates of the mirror",
    )
    return parser
