import json
import logging

from .json import dumps


def main(argv):
    logging.basicConfig()
    print(dumps(json.loads(argv[1])))
