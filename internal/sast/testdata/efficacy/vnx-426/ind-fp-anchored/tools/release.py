import ctypes
import ctypes.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(sys.prefix, "share", "acme"))
sys.path.insert(0, "/opt/acme/lib/python")

libc = ctypes.CDLL("libc.so.6")
k32 = ctypes.WinDLL("kernel32")
ssl = ctypes.CDLL(ctypes.util.find_library("ssl"))
fast = ctypes.CDLL(os.path.join(HERE, "libfast.so"))


def run(target):
    subprocess.run(["git", "status"], check=True)
    subprocess.run(["./bin/deploy", target], cwd=HERE, check=True)
    subprocess.run([os.path.join(HERE, "bin", "deploy"), target], check=True)
    os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    # sys.path.insert(0, "") would trust the working directory
    print('call sys.path.append(".") to import local modules')
