~>import imp
~>from distutils.core import setup
~>import asynchat, os
~>from collections import Mapping


def load(path):
    return imp.load_source("plugin", path)
