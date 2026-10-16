int sum(const int *v, int len)
{
    int total;
    for (int i = 0; i < len; i++)
~>        total += v[i];
    return total;
}
