from decimal import Decimal
~>from shop.orders import Order, OrderStatus


def total(order: "Order") -> Decimal:
    return sum(i.price for i in order.items)
