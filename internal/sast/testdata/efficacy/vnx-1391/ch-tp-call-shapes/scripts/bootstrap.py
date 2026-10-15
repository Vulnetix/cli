import argparse
import os

~>os.environ.setdefault("REDIS_PASSWORD", "letmein")

parser = argparse.ArgumentParser()
~>parser.add_argument("-p", "--password", default="1q2w3e4r")
