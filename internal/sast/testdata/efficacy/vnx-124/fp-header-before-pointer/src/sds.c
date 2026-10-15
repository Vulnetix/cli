typedef char *sds;

void set_type(sds s, unsigned char type)
{
    s[-1] = type;
    ((void **)s)[-1] = 0;
}

int last(const int *values, int count)
{
    return values[count - 1];
}
