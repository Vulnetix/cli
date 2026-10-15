import os
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("root")
args = parser.parse_args()
root = sys.argv[1]
os.chroot(args.root)
sys.path.insert(0, root)
