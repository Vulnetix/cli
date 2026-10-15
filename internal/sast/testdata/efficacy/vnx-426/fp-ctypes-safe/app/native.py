import ctypes
import ctypes.util
import os

libc = ctypes.CDLL("libc.so.6")
k32 = ctypes.WinDLL("kernel32")
user = ctypes.windll.LoadLibrary("user32.dll")
ssl = ctypes.CDLL(ctypes.util.find_library("ssl"))
here = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libfast.so"))
abs_lib = ctypes.CDLL("/opt/app/lib/libfast.so")
