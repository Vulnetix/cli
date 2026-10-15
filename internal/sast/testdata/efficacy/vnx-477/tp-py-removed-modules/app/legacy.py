~>import imp
~>import asyncore
~>import cgi, os
~>from distutils.core import setup
~>from distutils import sysconfig
~>import telnetlib as tn
~>from collections import Mapping, OrderedDict
~>import xml.etree.cElementTree as ET


def load(name, path):
    return imp.load_source(name, path)
