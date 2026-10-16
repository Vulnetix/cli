import subprocess
import sys

sys.path.insert(0, ".")


def test_help():
    subprocess.run(["./bin/acme", "--help"], check=True)
