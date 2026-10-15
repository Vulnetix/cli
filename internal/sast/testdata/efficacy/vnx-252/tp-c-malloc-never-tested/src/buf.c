#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *dup_name(const char *name, size_t n)
{
~>    char *copy = malloc(n + 1);
    memcpy(copy, name, n);
    copy[n] = '\0';
    return copy;
}

void dump(const char *path)
{
~>    FILE *fp = fopen(path, "w");
    fprintf(fp, "state\n");
    fclose(fp);
}
