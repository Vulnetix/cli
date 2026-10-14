#include <stdlib.h>

int *make_grid(int argc, char **argv)
{
    int width = atoi(argv[1]);
    int height = atoi(argv[2]);
    size_t bytes = width * height * sizeof(int);

~>    int *cells = malloc(bytes);
    return cells;
}

long *make_row(const char *arg)
{
    long n = strtol(arg, NULL, 10);
~>    return (long *)malloc(sizeof(long) *
                          n);
}

char *env_buffer(void)
{
~>    return malloc(atoi(getenv("BUF_COUNT")) * 64);
}
