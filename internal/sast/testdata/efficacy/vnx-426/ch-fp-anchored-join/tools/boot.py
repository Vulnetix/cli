import os
import subprocess
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))

subprocess.run(
    ["scripts/gen.sh"],
    cwd=HERE,
    check=True,
)
subprocess.run(["git", "rev-parse", "HEAD"], check=True)
