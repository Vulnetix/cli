import subprocess


def listing(path):
    return subprocess.run(["ls", "-la", path], check=True)


def clone(url):
    subprocess.run(f"git clone {url}".split(), shell=False)


def build():
    subprocess.run("make clean && make", shell=True)
    subprocess.check_call(["bash", "-c", "echo ready"])
