import ctypes
import os
import site

HERE = os.path.dirname(os.path.abspath(__file__))
site.addsitedir(os.path.join(HERE, "deps"))

SCANNER_LIB = os.path.join(HERE, "native", "libscan.so")
SYSTEM_LIB = "libz.so.1"


def load():
    ctypes.CDLL(SYSTEM_LIB)
    return ctypes.CDLL(SCANNER_LIB)
