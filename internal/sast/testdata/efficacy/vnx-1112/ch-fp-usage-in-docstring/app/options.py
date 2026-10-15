"""Shared option helpers.

Typical use::

    parser = argparse.ArgumentParser()
    parser.add_argument("--profile")
    add_common(parser)
"""
import argparse


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="named settings profile")
