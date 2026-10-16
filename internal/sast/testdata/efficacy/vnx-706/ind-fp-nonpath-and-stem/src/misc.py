import os

# if os.path.commonprefix([a, b]) != a: nope
doc = "os.path.realpath(x).startswith(ROOT)"


def stem(names):
    common = os.path.commonprefix(names)
    return common.rstrip("_")


def scheme(url):
    return url.startswith("https")
