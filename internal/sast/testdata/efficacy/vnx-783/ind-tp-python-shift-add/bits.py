def check(flags, MASK, hi, lo):
    if flags & MASK == 0:
        return 0
~>    return hi << 8 + lo
