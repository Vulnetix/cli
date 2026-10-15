import ctypes
import os

lib = ctypes.CDLL("./plugins/libauth.so")
os.environ["PATH"] = ".:/usr/bin"
