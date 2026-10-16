#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    int count = atoi(argv[1]);
~>    int *items = malloc(count * sizeof(int));
    for (int i = 0; i < count; i++)
        items[i] = i;
    free(items);
    return 0;
}
