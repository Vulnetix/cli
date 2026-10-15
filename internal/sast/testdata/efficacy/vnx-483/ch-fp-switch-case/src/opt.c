int opt(int c, int *verbose)
{
    switch (c) {
    case 'v':
        if (*verbose < 3)
            (*verbose)++;
        break;
    case 'q':
        *verbose = 0;
        break;
    }
    return 0;
}
