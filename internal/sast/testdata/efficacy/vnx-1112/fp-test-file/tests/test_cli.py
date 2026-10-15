import argparse


def test_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--x")
    assert parser.parse_args(["--x", "1"]).x == "1"
