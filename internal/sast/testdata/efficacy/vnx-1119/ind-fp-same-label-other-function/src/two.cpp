int a()
{
out:
    return 0;
}

int b(int x)
{
    if (x)
        goto out;
    return 1;
out:
    return 2;
}
