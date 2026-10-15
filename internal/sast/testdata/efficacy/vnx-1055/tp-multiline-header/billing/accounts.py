from dataclasses import dataclass


class Customer:
    tier = "standard"

    def discount(self):
        return 0


class Vendor:
    payment_terms = 30

    def discount(self):
        return 5


class Auditable:
    audited = True


~>class Partner(
    Customer,
    Vendor,
    Auditable,
):
    pass


class LoggingMixin:
    def log(self, msg):
        print(msg)


~>class Reseller(LoggingMixin, Customer, Vendor):
    pass
