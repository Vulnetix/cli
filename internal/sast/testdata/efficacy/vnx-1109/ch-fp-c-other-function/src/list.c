static int count(const int *v, int n)
{
    int i, c = 0;
    for (i = 0; i < n; i++) {
        if (v[i]) {
            c++;
        }
    }
    return c;
}

static void clear(int *v, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        v[i] = 0;
    }
}
