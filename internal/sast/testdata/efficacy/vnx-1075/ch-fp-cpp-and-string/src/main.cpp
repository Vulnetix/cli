int spin(int n)
{
loop:
    if (--n > 0)
        goto loop;
    return n;
}
