import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="Sync the mirror")
    parser.add_argument("--source", required=True)
~>    parser.add_argument("--verify-tls", type=bool, default=True,
                        help="verify the upstream certificate")
    parser.add_argument(
~>        "--dry-run", default=False, type=bool)
    return parser.parse_args()
