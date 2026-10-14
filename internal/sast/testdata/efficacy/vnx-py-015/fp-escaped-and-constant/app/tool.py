import argparse
import re

from flask import request

PATTERN = r"^v(\d+)\.(\d+)$"


def search():
    q = request.args.get("q")
    literal = re.compile(re.escape(q))
    hit = re.search(re.escape(request.args["needle"]), TEXT)
    ver = re.compile(PATTERN)
    return literal, hit, ver


def main():
    args = argparse.ArgumentParser().parse_args()
    pattern = CONFIG["pattern"]
    return re.compile(pattern), re.compile(args.pattern)
