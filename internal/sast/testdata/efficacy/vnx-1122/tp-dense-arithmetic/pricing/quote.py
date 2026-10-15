def quote(base, qty, tax, fee, disc, ship, w, h, d):
~>    total = base * qty + base * qty * tax / 100 - disc * qty + fee + ship * w * h * d / 5000 - (disc > 10) * fee // 2 % 7
    return total
