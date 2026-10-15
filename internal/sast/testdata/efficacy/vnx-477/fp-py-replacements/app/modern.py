import base64
import collections
import html
import importlib
import inspect
import logging
import ssl
import time
from collections.abc import Mapping
from collections import OrderedDict, defaultdict
import xml.etree.ElementTree as ET
from setuptools import setup

log = logging.getLogger(__name__)


def connect(sock, host):
    ctx = ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=host)


def describe(name):
    blob = base64.encodebytes(name.encode())
    log.warning("name %s", html.escape(name))
    counts = collections.Counter(name)
    return blob, time.perf_counter(), inspect.signature(describe), counts


def is_map(x):
    return isinstance(x, Mapping)
