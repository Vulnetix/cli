int ok(int a, int *b)
{
    if (a > 0) {
        b[0] = 1;
        b[1] = 2;
    }
    if (a < 0)
        b[0] = -1;
    b[1] = 0;
    if (a == 3)
        return 3;

    b[2] = 3;
    if (a == 4) b[0] = 4;
    b[3] = 4;
    if (a == 5)
        b[0] = 5;
    else
        b[0] = 6;
    if (a)
        foo();
    else if (b)
        bar();
    if (a) return f(a);
    return 0;
}
