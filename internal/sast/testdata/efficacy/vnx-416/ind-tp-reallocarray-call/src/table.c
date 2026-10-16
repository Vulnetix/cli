#include <stdlib.h>

int table_add(struct entry *entries, size_t n, struct entry e, struct entry **out)
{
    struct entry *bigger = reallocarray(entries, n + 1, sizeof(*entries));
    if (!bigger)
        return -1;
    bigger[n] = e;
~>    qsort(entries, n + 1, sizeof(*entries), cmp_entry);
    *out = bigger;
    return 0;
}

char *grow_name(char *name, size_t want)
{
    char *nn = g_realloc(name, want);
    nn[want - 1] = '\0';
~>    return name;
}
