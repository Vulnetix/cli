import ctypes
from ctypes import CDLL, WinDLL

~>lib = ctypes.CDLL("./libfast.so")
~>codec = CDLL("vendor/libcodec.so")
~>helper = WinDLL("helper.dll")
~>legacy = ctypes.windll.LoadLibrary("legacyapi.dll")
