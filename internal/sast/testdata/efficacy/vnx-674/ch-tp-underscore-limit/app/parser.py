import sys

~>sys.setrecursionlimit(1_000_000)


def parse(doc):
    return walk(doc)
