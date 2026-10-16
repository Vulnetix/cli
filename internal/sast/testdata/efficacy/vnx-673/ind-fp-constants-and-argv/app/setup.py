import os
import sys
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

sys.path.insert(0, str(BASE_DIR / "vendor"))
sys.path.append(os.path.join(os.path.dirname(__file__), "lib"))

parser = argparse.ArgumentParser()
parser.add_argument("--root")
args = parser.parse_args()
os.chroot(args.root)
sys.path.insert(0, sys.argv[1])
os.environ["PATH"] = "/usr/local/bin:" + os.environ["PATH"]
