import ctypes

def wipe(buf):
    ctypes.memset(buf, sizeof(buf), 0)
    fputs(stderr, "x")
