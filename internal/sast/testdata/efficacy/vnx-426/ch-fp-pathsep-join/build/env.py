import os

BIN_DIR = "/opt/tool/bin"


def setup():
    os.environ["PATH"] = os.pathsep.join([BIN_DIR, os.environ["PATH"]])
    os.environ["PYTHONPATH"] = os.pathsep.join(["/opt/tool/lib", os.environ.get("PYTHONPATH", "/usr/lib")])
    os.environ["PATH"] = "/usr/local/bin" + os.pathsep + os.environ["PATH"]
