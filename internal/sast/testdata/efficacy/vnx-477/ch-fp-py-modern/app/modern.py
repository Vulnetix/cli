import base64
import importlib.util
import inspect
import time
from collections.abc import Mapping
from setuptools import setup


def encode(data):
    return base64.encodebytes(data)


def describe(fn):
    return inspect.getfullargspec(fn).args


def elapsed():
    return time.perf_counter()


def load(path):
    spec = importlib.util.spec_from_file_location("plugin", path)
    return spec
