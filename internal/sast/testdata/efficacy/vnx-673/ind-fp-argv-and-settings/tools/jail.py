import argparse
import os
import sys

from django.conf import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "vendor"))
sys.path.append(settings.PLUGIN_DIR)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    args = parser.parse_args()
    os.chroot(args.root)
    os.environ["LD_LIBRARY_PATH"] = sys.argv[2]
