import unittest


class MathTest(unittest.TestCase):
    def test_add(self):
~>        self.assertEquals(1 + 1, 2)
~>        self.assertItemsEqual([1, 2], [2, 1])
~>        self.assertRegexpMatches("abc", "b")
~>        self.failUnless(True)
