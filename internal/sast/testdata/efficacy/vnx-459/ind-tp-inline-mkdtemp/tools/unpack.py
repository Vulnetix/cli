import subprocess
import tempfile


def unpack(archive):
~>    subprocess.run(["unzip", "-q", archive, "-d", tempfile.mkdtemp()], check=True)
