import unittest

from pkg.merge import deep_merge


class MergeTest(unittest.TestCase):
    def test_nested(self):
~>        self.assertEquals(deep_merge({"a": {"b": 1}}, {"a": {"c": 2}}), {"a": {"b": 1, "c": 2}})
