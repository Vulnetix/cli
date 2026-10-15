import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--output", default="out.csv", help="where to write")
parser.add_argument('--limit', type=int, help='maximum rows')
