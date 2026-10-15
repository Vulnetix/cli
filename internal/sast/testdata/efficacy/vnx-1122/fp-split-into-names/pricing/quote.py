def quote(base, qty, tax, fee, disc, ship, w, h, d):
    subtotal = base * qty
    taxes = subtotal * tax / 100
    discount = disc * qty
    volume = w * h * d / 5000
    total = (subtotal + taxes - discount + fee
             + ship * volume - (disc > 10) * fee // 2 % 7)
    return total


def wrapper(*args, **kwargs) -> int:
    return call(*args, **kwargs)


def area(a, b, c, d, e):
    return a * b + c * d - e / 2 + a - b + c - d * e + a * b * c % 7 - 1
