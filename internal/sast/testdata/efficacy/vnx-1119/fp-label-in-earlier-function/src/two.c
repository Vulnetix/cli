int first(int x)
{
done:
    return x;
}

int second(int y)
{
    if (y < 0)
        goto done;
    y++;
done:
    return y;
}
