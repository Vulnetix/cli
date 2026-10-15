int clamp(int x, int lo, int hi)
{
    if (x <= lo)
        return lo;
    if (x >= hi)
        return hi;
    while (x != lo && x == hi)
        x--;
    for (int i = 0; i < x; i++)
        lo++;
    return x;
}
