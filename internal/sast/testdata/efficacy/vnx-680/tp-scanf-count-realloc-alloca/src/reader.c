#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

char *grow(FILE *fp, char *items) {
    unsigned int n;
    unsigned short width;
    fscanf(fp, "%u", &n);
    fread(&width, sizeof(width), 1, fp);
~>    items = realloc(items, n * width);
~>    char *scratch = alloca(n *
        sizeof(char));
    scratch[0] = 0;
    return items;
}
