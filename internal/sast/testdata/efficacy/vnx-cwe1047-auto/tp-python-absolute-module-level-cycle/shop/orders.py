import enum
from dataclasses import dataclass

from shop.billing import charge


class OrderStatus(enum.Enum):
    OPEN = 1
    PAID = 2


@dataclass
class Order:
    total: int
    status: OrderStatus = OrderStatus.OPEN

    def pay(self):
        amount = charge(self)
        self.status = OrderStatus.PAID
        return amount
