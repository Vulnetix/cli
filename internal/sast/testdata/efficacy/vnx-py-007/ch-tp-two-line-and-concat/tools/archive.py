import subprocess


def extract(archive, dest):
    cmd = f"tar xzf {archive} -C {dest}"
~>    subprocess.call(cmd, shell=True)


def listing(path):
~>    return subprocess.check_output("ls -la " + path, shell=True)
