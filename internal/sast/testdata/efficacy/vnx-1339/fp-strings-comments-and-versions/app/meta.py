import sys

# never write x == 0.1, compare with math.isclose
VERSION = "1.2.3"


def info(version):
    print("x == 0.1 is false for 0.1 + 0.2")
    if version == "3.10":
        return VERSION
    return sys.version_info >= (3, 10)
