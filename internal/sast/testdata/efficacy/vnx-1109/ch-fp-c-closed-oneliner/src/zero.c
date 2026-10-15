void reset(int *a, int *b, int n)
{
    int i;
    for (i = 0; i < n; i++) { a[i] = 0; }
    for (i = 0; i < n; i++) {
        b[i] = a[i];
    }
}
