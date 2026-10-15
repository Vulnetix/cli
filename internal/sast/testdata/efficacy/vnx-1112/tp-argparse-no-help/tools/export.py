import argparse


def main():
    parser = argparse.ArgumentParser(description="Export records")
    parser.add_argument("--input", help="file to read")
~>    parser.add_argument("--output", default="out.csv")
~>    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()
    return args
