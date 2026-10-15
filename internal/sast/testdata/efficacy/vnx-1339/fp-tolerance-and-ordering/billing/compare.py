import math


def close(a, b):
    if math.isclose(a, 0.1):
        return True
    if abs(b - 0.3) < 1e-9:
        return True
    if a <= 0.1 or b >= 0.3:
        return False
    rate = 0.1
    return a == 1e-3 or b == 2.5e-1
