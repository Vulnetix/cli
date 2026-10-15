import pytest

from money import Money


def test_compare_currency_mismatch():
    with pytest.raises(TypeError):
        Money(1, "USD") == Money(1, "EUR")


class MoneyTest(unittest.TestCase):
    def test_eq_raises(self):
        with self.assertRaises(ValueError):
            self.a == self.b
