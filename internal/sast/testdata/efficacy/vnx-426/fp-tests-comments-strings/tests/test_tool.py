import subprocess
import sys

sys.path.insert(0, ".")


def test_cli():
    subprocess.run(["./bin/tool", "--help"], check=True)
