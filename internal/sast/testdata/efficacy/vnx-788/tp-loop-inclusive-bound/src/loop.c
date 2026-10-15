#define N 10

int sum(void)
{
    int vals[N];
    int total = 0;
    int i;
~>    for (i = 0; i <= N; i++) {
        total += vals[i];
    }
    return total;
}

void clear(void)
{
    char buf[256];
~>    for (int k = 0; k <= sizeof(buf); k++)
        buf[k] = 0;
}
