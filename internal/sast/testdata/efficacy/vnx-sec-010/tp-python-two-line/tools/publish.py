import subprocess

~>TOKEN = "pypi-AgEIcHlwaS5vcmc@@sample:[A-Za-z0-9_\-]{80}@@"


def upload(dist_dir):
    subprocess.run(["twine", "upload", "-u", "__token__", "-p", TOKEN, dist_dir], check=True)
