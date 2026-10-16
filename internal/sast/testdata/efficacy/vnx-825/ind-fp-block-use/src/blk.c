void k(int cond)
{
    int *p;
    {
        int inner = 5;
        p = &inner;
        *p = 6;
    }
    int total = cond;
    (void)total;
}
