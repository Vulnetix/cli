int total(void)
{
    int vals[16];
    int i, sum = 0;
~>    for (i = 0; i <= 16; i++)
        sum += vals[i];
    return sum;
}
