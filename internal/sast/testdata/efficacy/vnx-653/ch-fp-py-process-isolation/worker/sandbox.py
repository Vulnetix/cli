import subprocess
import sys

FORBIDDEN = "__builtins__"


def run_untrusted(code):
    return subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        timeout=5,
    )
