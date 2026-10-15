void fill(int *out, int n)
{
    int buf[16];
    for (int i = 0; i <= 15; i++)
        buf[i] = i;
    for (int j = 0; j < 16; j++)
        out[j] = buf[j];
    for (int k = 0; k <= n - 1; k++)
        out[k] = 0;
}
