int next(FILE *f)
{
again:
    int c = getc(f);
    if (c == ' ')
        goto again;
    return c;
}
