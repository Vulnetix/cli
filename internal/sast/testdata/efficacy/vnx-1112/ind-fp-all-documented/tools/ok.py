import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--output", default="out.csv", help="where to write")
parser.add_argument(
    "--retries",
    type=int,
    help="number of retries",
)
parser.add_argument("--internal", help=argparse.SUPPRESS)
parser.add_argument("--version", action="version", version="1.0")
group = parser.add_argument_group("advanced")
excl = parser.add_mutually_exclusive_group()
