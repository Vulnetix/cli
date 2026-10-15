int delta(int a[], int b[], int i)
{
    int x = a[i];
    int y = b[i];
    int d = y - x;
    return d - (a[0] - b[0]);
}

long width(long right, long left)
{
    return right - left;
}
