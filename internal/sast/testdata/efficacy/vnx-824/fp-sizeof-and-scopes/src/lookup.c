#include <stdlib.h>

typedef struct entry { unsigned long id; void *value; } entry;

void *lookup(unsigned long id)
{
    static struct {
        unsigned long id;
        entry *e;
    } cache[16];
    for (int j = 0; j < 16 && cache[j].e != NULL; j++)
        if (cache[j].id == id) return cache[j].e;
    entry *e = NULL;
    return e;
}

int header_fits(size_t len)
{
    struct entry *hdr;
    if (len < sizeof(*hdr)) return 0;
    return 1;
}

void scoped(int n)
{
    entry *node;
    for (int i = 0; i < n; i++) {
        entry *node = calloc(1, sizeof(entry));
        node->id = i;
        free(node);
    }
}
