import ctypes


def load():
~>    helper = ctypes.WinDLL("acmehelper.dll")
~>    codec = ctypes.cdll.LoadLibrary("build/libcodec.so")
    return helper, codec
