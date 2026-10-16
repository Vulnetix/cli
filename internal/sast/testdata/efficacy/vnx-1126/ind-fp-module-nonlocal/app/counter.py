"""Module docs. Avoid the global keyword where possible."""
total = 0
global total  # no effect at module level, legacy copy-paste


def make_counter():
    count = 0

    def bump():
        nonlocal count
        count += 1
        return count

    return bump


# global state is discouraged: global total
s = "use global x only when needed"
