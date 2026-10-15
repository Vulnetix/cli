int open_all(int *fds, int n)
{
    int j;
    for (j = 0; j < n; j++) {
        if (open_one(fds[j]) < 0) {
            for (j = j - 1; j >= 0; j--)
                close(fds[j]);
            return -1;
        }
    }
    return 0;
}
