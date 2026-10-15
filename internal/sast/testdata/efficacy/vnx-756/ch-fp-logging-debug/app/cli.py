import argparse
import logging

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", default=False)
args = parser.parse_args()
logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
config = {"debug": True}  # feature flag for the CLI, not a web server
