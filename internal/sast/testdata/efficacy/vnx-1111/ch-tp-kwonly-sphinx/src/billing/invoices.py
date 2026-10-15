from decimal import Decimal


~>def issue_invoice(customer_id: str,
                  amount: Decimal,
                  *,
                  currency: str = "EUR",
                  due_days: int = 30) -> str:
    """Create an invoice and return its number.

    :param customer_id: the customer to bill
    :param amount: total including tax
    :param currency: ISO 4217 code
    :returns: the invoice number
    """
    return f"{customer_id}-{amount}-{currency}-{due_days}"
