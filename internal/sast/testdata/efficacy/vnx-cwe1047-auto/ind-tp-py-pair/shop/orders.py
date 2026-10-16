from shop.billing import total


class Order:
    def __init__(self, items):
        self.items = items

    def amount(self):
        return total(self)
