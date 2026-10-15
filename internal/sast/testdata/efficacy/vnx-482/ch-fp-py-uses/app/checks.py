def same(a, b):
    ok = a == b
    print(a == b)
    assert a == b, "mismatch"
    values = [x for x in range(10)
              if x == a]
    flag = (
        a == b
    )
    return a == b or ok


def helper(a, b):
    return all(
        a == b
        for _ in range(3)
    )
