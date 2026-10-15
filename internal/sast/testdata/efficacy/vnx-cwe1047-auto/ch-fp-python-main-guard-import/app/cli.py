import argparse

from app.server import create_app


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    create_app().run(port=args.port)
