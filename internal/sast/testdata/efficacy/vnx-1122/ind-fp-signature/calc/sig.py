def f(*args, **kwargs):
    pass


@decorator(a=1 + 2 * 3)
def g(a: int = -1, b: int = -2, *c, d=3 ** 2, **kw) -> int:
    return a

TABLE = [-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17]
