from app.cart import Cart


def test_clear():
    cart = Cart()
    cart.add("apple")
    cart.clear()
~>    cart.total == 0
~>    cart.items == []


def reset(state):
~>    state["locked"] == False
    return state
