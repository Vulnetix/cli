import os
import sys
from pathlib import Path


def self_update(new_source):
~>    with open(os.path.abspath(__file__), "w") as fh:
        fh.write(new_source)


def stamp(src):
~>    with Path(__file__).resolve().open("w") as fh:
        fh.write(src)


def append_marker():
~>    with open(os.path.realpath(sys.argv[0]), mode="a") as fh:
        fh.write("# seen\n")
