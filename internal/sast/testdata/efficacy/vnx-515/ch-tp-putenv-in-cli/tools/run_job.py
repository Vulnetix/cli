import os
import sys


def main(argv):
    api_key = argv[1]
~>    os.putenv("STRIPE_API_KEY", api_key)
~>    os.environ.setdefault("SERVICE_SECRET", argv[2])
    os.execvp("worker", ["worker"])


if __name__ == "__main__":
    main(sys.argv)
