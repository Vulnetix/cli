import shutil
import subprocess
import tempfile


def build_archive(src):
    workdir = tempfile.mkdtemp(prefix="build-")
    try:
        subprocess.run(["make", "-C", workdir], check=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
