import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "--since",
    type=str,
    help="only export records after this date",
)
