int pick(int a, int b)
{
    int r;
    if (a > b)
        r = a;
    else if (b > a)
        r = b;
    else
        r = 0;
    return r;
}
