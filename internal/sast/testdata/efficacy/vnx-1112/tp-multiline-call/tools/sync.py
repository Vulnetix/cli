import argparse

parser = argparse.ArgumentParser()
~>parser.add_argument(
    "--retries",
    type=int,
    default=3,
)
