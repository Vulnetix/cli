int f(void)
{
    int x;
    /* x++ would read an indeterminate value here */
    // return x;
    x = 3;
    return x;
}
