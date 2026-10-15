import argparse


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument("--password", required=True, help="never leave it as password or admin")
    p.add_argument("--password-file", default="/run/secrets/db")
    return p


ERROR = "password must not be 'admin'"
