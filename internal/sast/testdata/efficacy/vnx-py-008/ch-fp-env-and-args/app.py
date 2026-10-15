import argparse
import logging
import os

from flask import Flask

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    app.run(debug=args.debug)
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
    app.run(debug=False)
