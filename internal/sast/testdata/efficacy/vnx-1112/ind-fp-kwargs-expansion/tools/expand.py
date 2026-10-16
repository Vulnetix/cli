import argparse

COMMON = {"help": "shared"}
parser = argparse.ArgumentParser()
parser.add_argument("--level", **COMMON)
parser.add_argument("--zone", **opts)
