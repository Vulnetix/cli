from argparse import ArgumentParser

parser = ArgumentParser(prog="rotate")
mode = parser.add_mutually_exclusive_group(required=True)
~>mode.add_argument("--all", action="store_true")
mode.add_argument("--key-id", help="rotate only this key")
