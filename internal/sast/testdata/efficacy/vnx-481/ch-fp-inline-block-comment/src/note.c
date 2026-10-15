int note(int a, int b)
{
    a++; /* was: if (a = b) */
    if (a == b) /* not if (a = b) */
        return 1;
    return 0;
}
