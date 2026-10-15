import os
import subprocess


def build_env():
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    return env


def run(cmd):
    return subprocess.run(cmd, env=os.environ.copy(), check=True)


def healthz():
    return {"status": "ok", "version": os.environ.get("APP_VERSION")}
