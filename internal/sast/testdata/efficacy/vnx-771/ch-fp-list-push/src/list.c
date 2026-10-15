#include <stdlib.h>

struct node { int v; struct node *next; };

struct node *build(int n)
{
    struct node *head = NULL;
    struct node *node = malloc(sizeof *node);
    node->next = head;
    head = node;
    node = malloc(sizeof *node);
    node->next = head;
    head = node;
    return head;
}
