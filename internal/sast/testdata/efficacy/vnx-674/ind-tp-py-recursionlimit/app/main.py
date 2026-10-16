import sys
import json

~>sys.setrecursionlimit(100000)


def parse(raw):
    return json.loads(raw)
