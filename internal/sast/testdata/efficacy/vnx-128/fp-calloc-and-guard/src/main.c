#include <stdint.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int count = atoi(argv[1]);
    int *items = calloc(count, sizeof(int));
    size_t n = strtoul(argv[2], NULL, 10);
    if (n > SIZE_MAX / sizeof(long))
        return 1;
    long *extra = malloc(n * sizeof(long));
    unsigned m = strtoul(argv[3], NULL, 10);
    if (m == 0 || m > 4096)
        return 1;
    char *b = malloc(m * 16);
    free(items);
    return 0;
}
