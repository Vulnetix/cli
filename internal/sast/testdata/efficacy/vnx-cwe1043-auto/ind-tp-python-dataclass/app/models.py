from dataclasses import dataclass
from typing import Optional


@dataclass
~>class Checkout:
    customer: Customer
    cart: Cart
    billing: Address
    shipping: Address
    payment: Payment
    coupon: Optional[Coupon]
    carrier: Carrier
    tax: TaxPolicy
    invoice: Invoice
    audit: AuditLog
    warehouse: Warehouse
    note: str
    total: int
