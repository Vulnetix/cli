from shop.cart import Cart


def test_clear_resets_total():
    cart = Cart()
    cart.add("apple", 3)
    cart.clear()
~>    cart.total == 0
