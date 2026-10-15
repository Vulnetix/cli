int flags(int x)
{
    if (x)
        /* only set when x is non-zero */
        x |= 4;
    while (x > 8)
        x >>= 1;
    return x;
}
