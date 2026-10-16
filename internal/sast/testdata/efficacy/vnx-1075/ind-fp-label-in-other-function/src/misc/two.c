int first(void)
{
retry:
    if (poll() == 0)
        return 1;
    return 0;
}

int second(int x)
{
    if (x > 3)
        goto retry;
    return 0;
retry:
    return x;
}
