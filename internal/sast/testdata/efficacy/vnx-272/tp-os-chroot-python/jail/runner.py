import os
import sys


def serve(jail_dir, request_path):
~>    os.chroot(jail_dir)
    os.chdir("/")
    with open(request_path, "rb") as handle:
        sys.stdout.buffer.write(handle.read())


if __name__ == "__main__":
    serve(sys.argv[1], sys.argv[2])
