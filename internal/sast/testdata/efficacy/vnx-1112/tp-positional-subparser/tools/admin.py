import argparse

root = argparse.ArgumentParser(prog="admin")
subs = root.add_subparsers(dest="cmd")
sync = subs.add_parser("sync", help="synchronise a target")
~>sync.add_argument("target")
