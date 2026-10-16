import hashlib
import subprocess
from urllib.request import urlretrieve

AGENT = "https://downloads.example.com/agent/install.sh"
AGENT_SHA256 = "9f2c6b0e1d4a7f3e8b5c2a1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f"


def main():
    path, _ = urlretrieve(AGENT, "/tmp/install.sh")
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != AGENT_SHA256:
        raise SystemExit("checksum mismatch")
    subprocess.check_call(["/bin/sh", path])
