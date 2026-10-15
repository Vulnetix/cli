int adjust(int n)
{
    int offset = -1;
    int step = +2;
    n -= offset;
    n += step;
    n = -n;
    return n;
}
