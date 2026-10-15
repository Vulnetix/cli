#include <stdlib.h>

struct node {
    int value;
    struct node *next;
};

struct node *push(struct node *head, int value)
{
    struct node *n = calloc(1, sizeof(*n));
~>    n->value = value;
    n->next = head;
    return n;
}
