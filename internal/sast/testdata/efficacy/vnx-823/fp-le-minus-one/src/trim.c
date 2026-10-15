void trim(char *out)
{
    char name[32];
    for (unsigned i = 0; i <= sizeof(name) - 1; i++)
        name[i] = 0;
    int counts[4];
    for (int i = 0; i <= sizeof(counts); i++)
        out[i] = 0;
    (void)counts;
}
