int prev_char(const char *p)
{
    /* p points inside a buffer, so p[-1] is the previous byte */
    return p[-1];
}

int stack_top(int *sp)
{
    return sp[-1];
}
