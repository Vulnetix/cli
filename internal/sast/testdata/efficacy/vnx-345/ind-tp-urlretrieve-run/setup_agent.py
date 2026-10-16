import os
import subprocess
from urllib.request import urlretrieve

AGENT = "https://downloads.example.com/agent/install.sh"


def main():
    path, _ = urlretrieve(AGENT, "/tmp/install.sh")
    os.chmod(path, 0o755)
~>    subprocess.check_call(["/bin/sh", path])


if __name__ == "__main__":
    main()
