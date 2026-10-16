import pytest

from shop.cart import Cart


def test_clear():
    """cart.total == 0 after clear"""
    cart = Cart()
    cart.clear()
    assert cart.total == 0
    ok = cart.items == []
    assert ok


def test_eq_raises():
    with pytest.raises(TypeError):
        Cart() == object()
