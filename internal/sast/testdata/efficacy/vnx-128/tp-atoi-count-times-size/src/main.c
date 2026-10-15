#include <stdlib.h>

int main(int argc, char **argv)
{
    int count = atoi(argv[1]);
~>    int *items = malloc(count * sizeof(int));
~>    long *extra = (long *) malloc(atoi(argv[2]) * sizeof(long));
    free(items);
    free(extra);
    return 0;
}
