#include <stdio.h>
#include <stdlib.h>

int load(FILE *fp, int **out)
{
    unsigned int count;
    int *items = NULL;
    fread(&count, sizeof count, 1, fp);
~>    items = realloc(items, count * sizeof(int));
    *out = items;
    return 0;
}
