"""Billing for orders."""
import decimal

~>from shop.orders import Order, OrderStatus

TAX = decimal.Decimal("0.2")


def charge(order: Order) -> decimal.Decimal:
    if order.status is not OrderStatus.OPEN:
        raise ValueError("order is closed")
    return order.total * (1 + TAX)
