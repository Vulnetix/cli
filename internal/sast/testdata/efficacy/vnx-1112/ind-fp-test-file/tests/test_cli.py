import argparse


def make():
    p = argparse.ArgumentParser()
    p.add_argument("--flag", action="store_true")
    return p
