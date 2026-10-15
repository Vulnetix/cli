import subprocess
import tempfile


def build_archive(src):
~>    workdir = tempfile.mkdtemp(prefix="build-")
    subprocess.run(["tar", "-xf", src, "-C", workdir], check=True)
    subprocess.run(["make", "-C", workdir], check=True)
    print("built in", workdir)
