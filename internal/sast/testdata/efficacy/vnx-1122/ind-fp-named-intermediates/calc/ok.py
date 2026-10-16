def f(base, qty, tax, discount, fee):
    subtotal = base * qty
    taxes = subtotal * tax / 100
    total = subtotal + taxes - discount + fee
    return total
