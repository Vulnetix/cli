int cmp(int a, int b)
{
    int r = 0;
    if (a == b) r = 1;
    if (a <= b) r = 2;
    if (a >= b) r = 3;
    if (a != b) r = 4;
    for (r = 0; r < 3; r++)
        a = b;
    return r;
}
