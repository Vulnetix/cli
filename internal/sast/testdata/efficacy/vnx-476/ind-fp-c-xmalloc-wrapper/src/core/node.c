#include <string.h>
#include "xalloc.h"

struct node *node_new(const char *name)
{
    struct node *n = xmalloc(sizeof(*n));
    n->name = xstrdup(name);
    n->next = NULL;
    return n;
}
