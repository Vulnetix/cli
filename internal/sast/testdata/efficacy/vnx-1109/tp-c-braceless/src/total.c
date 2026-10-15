int total(int *a, int n, int m)
{
    int i, x = 0;
    for (i = 0; i < n; i++)
~>        for (i = 0; i < m; i++)
            x += a[i];
    for (i = 0; i < n; i++)
        x--;
    for (i = 0; i < n; i++) x++;
    for (i = 0; i < m; i++)
        x++;
    return x;
}
