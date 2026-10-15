def mix(h, c, x, y, z, m, mask):
~>    h = ((h << 5) + h) ^ (c & 0xFF) ^ (h >> 27) + (x * 31) % m - (y | z) & mask + (x >> 3) * (y << 2)
    return h
