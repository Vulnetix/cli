#include <stddef.h>

struct dict;
struct obj { int encoding; void *ptr; };

struct dict *table_of(struct obj *o)
{
    struct dict *ht = NULL;
    unsigned char *p;
    int j = 3;

    switch (o->encoding) {
    case 1:
        ht = o->ptr;
        break;
    case 2:
        ht = (struct dict *) o->ptr;
        break;
    }
    if (ht == NULL)
        return NULL;

    switch (j % 2) {
    case 0: p = NULL; break;
    case 1: p = o->ptr; break;
    }
    return p ? ht : NULL;
}
