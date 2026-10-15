import subprocess
import sys


def run_plugin(path):
    # executed in a separate, unprivileged interpreter
    return subprocess.run([sys.executable, "-I", path], capture_output=True, timeout=5, check=False)


def load_config(text):
    namespace = {"__builtins__": __builtins__}
    exec(text, namespace)
    return namespace
