#include <stdlib.h>

struct node { int value; struct node *next; };

struct node *push(struct node *head, int v)
{
    struct node *n = (struct node *)malloc(sizeof(struct node));
~>    n->value = v;
    n->next = head;
    return n;
}
