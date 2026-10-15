import argparse

parser = argparse.ArgumentParser()
group = parser.add_argument_group("output")
# parser.add_argument("--legacy")
group.add_argument("--fmt", help="output format")
