import sys
import locale
import unittest
import xml.etree.ElementTree as ET


def configure():
~>    sys.setcheckinterval(100)
~>    return locale.format("%d", 1234567, grouping=True)


def children(xml_text):
    root = ET.fromstring(xml_text)
~>    return root.getchildren()


def suite():
~>    return unittest.makeSuite(LegacyTests)
