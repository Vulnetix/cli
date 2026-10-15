int logic(int a, int b, int c, int *p, int x, int ok)
{
    if (a && b == c)
        return 1;
    if (x == b && c)
        return 2;
    if (!a)
        return 3;
    if (!a == !b)
        return 4;
    if (!ok == 0)
        return 5;
    if (a != b)
        return 6;
    if (foo(&x == p))
        return 7;
    if (a == b || c != 0)
        return 8;
    return &x == p;
}
