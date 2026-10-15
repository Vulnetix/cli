#include "zmalloc.h"

typedef struct node { struct node *next; int v; } node;

node *push(node *head, int v)
{
    node *n = zmalloc(sizeof(*n));
    n->v = v;
    n->next = head;
    char *label = xstrdup("node");
    label[0] = 'N';
    return n;
}
