import locale
import unittest
import xml.etree.ElementTree as ET
from importlib import reload
from collections import OrderedDict, defaultdict
from collections.abc import Mapping


def fmt(n):
    return locale.format_string("%d", n, grouping=True)


def children(xml_text):
    return list(ET.fromstring(xml_text))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(ModernTests)


class Tree:
    def getchildren(self):
        return self._kids
