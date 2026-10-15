import ctypes
import os
import site

~>site.addsitedir(".")
~>site.addsitedir(os.getcwd())

SCANNER_LIB = "./native/libscan.so"


def load():
~>    return ctypes.CDLL(SCANNER_LIB)
