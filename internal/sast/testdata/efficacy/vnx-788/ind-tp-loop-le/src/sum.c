#define N 16

int total_vals(void)
{
    int vals[N];
    int i, total = 0;
    for (i = 0; i < N; i++)
        vals[i] = i;
~>    for (i = 0; i <= N; i++)
        total += vals[i];
    return total;
}
