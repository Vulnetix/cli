import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def build():
    subprocess.run(["git", "rev-parse", "HEAD"], check=True)
    os.system("ls -la /var/log")
    subprocess.call(["/usr/bin/rsync", "-a", "src/", "dst/"])
    subprocess.run(["./configure"], cwd=HERE, check=True)
    subprocess.run([os.path.join(HERE, "bin", "deploy")])
    subprocess.run(
        ["./bin/build"],
        cwd="/opt/app",
    )
