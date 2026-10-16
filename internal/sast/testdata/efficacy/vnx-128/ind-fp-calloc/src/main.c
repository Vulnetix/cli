#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    int count = atoi(argv[1]);
    int *items = calloc(count, sizeof(int));
    if (!items)
        return 1;
    free(items);
    return 0;
}
