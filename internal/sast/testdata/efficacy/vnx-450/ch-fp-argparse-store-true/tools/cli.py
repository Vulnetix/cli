import argparse

from .util import str2bool

parser = argparse.ArgumentParser()
parser.add_argument("--verbose", action="store_true")
parser.add_argument("--verify", type=str2bool, default=True)
parser.add_argument("--retries", type=int, default=3)
parser.add_argument("--debug", action=argparse.BooleanOptionalAction, default=False)
