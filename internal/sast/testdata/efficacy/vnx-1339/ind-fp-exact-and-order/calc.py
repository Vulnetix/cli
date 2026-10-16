import math
def f(x, y):
    if x == 0.5 or y == 1.0 or x == 0.0:
        return 1
    if x <= 0.3 and y > 0.1:
        return 2
    if math.isclose(x, 0.3):
        return 3
    if abs(x - 0.1) < 1e-9:
        return 4
    return 0
