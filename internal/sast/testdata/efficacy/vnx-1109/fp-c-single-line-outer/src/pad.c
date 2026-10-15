void pad(int n, int m)
{
    int j;
    while (n--) {
        for (j = 0; j < m; j++) putchar(32);
        for (j = 0; j < m; j++) putchar(45);
    }
}
