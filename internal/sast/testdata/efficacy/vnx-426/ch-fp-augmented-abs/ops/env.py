import os

LIB_DIR = "/opt/tool/lib"


def prepare():
    os.environ["PATH"] += os.pathsep + "/opt/tool/bin"
    os.environ["PYTHONPATH"] += ":" + LIB_DIR
    os.environ["LD_LIBRARY_PATH"] += os.pathsep + os.path.join(os.sep, "usr", "local", "lib")
