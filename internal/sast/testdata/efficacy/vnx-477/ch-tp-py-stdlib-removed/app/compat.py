import base64
import inspect
import platform
import time


def encode(data):
~>    return base64.encodestring(data)


def describe(fn):
~>    spec = inspect.getargspec(fn)
    return spec.args


def distro():
~>    return platform.linux_distribution()


def elapsed():
~>    return time.clock()
