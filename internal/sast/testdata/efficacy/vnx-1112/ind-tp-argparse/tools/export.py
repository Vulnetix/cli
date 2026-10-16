import argparse

parser = argparse.ArgumentParser(description="Export data")
parser.add_argument("--format", choices=["csv", "json"], help="Output format")
~>parser.add_argument("--output", default="out.csv")
~>parser.add_argument(
    "--retries",
    type=int,
    default=3,
)
args = parser.parse_args()
