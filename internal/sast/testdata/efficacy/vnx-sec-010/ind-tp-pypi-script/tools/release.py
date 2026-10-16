import subprocess
import sys

UPLOAD_USER = "__token__"
~>UPLOAD_TOKEN = "@@sample:pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{60}@@"


def upload(dist="dist/*"):
    cmd = ["twine", "upload", "-u", UPLOAD_USER, "-p", UPLOAD_TOKEN, dist]
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(upload())
