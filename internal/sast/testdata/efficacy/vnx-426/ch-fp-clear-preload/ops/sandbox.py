import os
import subprocess


def run_clean(cmd):
    os.environ["LD_PRELOAD"] = ""
    os.environ["PATH"] = "/usr/bin:/bin"
    env = {"PATH": "/usr/sbin:/usr/bin", "HOME": "/nonexistent"}
    print("never set PATH to '.:' + PATH")
    return subprocess.run(cmd, env=env, check=False)
