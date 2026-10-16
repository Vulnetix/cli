def f(xs):
    return [x for x in xs if x and x > 1 or x < -1 ]


def g0(xs):
    return sum(1 for x in xs if x > 0 and x < 100)


def g1(xs):
    return sum(1 for x in xs if x > 1 and x < 100)


def g2(xs):
    return sum(1 for x in xs if x > 2 and x < 100)


def g3(xs):
    return sum(1 for x in xs if x > 3 and x < 100)


def g4(xs):
    return sum(1 for x in xs if x > 4 and x < 100)
