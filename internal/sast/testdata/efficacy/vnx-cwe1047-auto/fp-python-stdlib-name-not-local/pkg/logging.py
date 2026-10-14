"""Project log helpers; the package's own modules use the standard library."""
from .cli import main

LEVEL = "INFO"


def run(argv):
    return main(argv)
