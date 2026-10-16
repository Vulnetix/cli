#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "strbuf.h"

char *dup_name(const char *name)
{
    size_t n = strlen(name);
~>    char *copy = malloc(n + 1);
    memcpy(copy, name, n);
    copy[n] = '\0';
    return copy;
}

void write_report(const char *path, const struct report *r)
{
~>    FILE *fp = fopen(path, "w");
    fprintf(fp, "total=%d\n", r->total);
    fprintf(fp, "failed=%d\n", r->failed);
    fclose(fp);
}

struct item *items_new(size_t count)
{
~>    struct item *items = calloc(count, sizeof(*items));
    items[0].id = 1;
    return items;
}
