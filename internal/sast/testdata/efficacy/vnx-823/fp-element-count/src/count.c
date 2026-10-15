long sum_values(void)
{
    int values[16];
    long total = 0;
    for (int *p = values; p < values + sizeof(values) / sizeof(values[0]); p++)
        total += *p;
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        total += values[i];
    return total;
}
