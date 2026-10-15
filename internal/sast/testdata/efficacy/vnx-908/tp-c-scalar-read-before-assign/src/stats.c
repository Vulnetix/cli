#include <stdio.h>

struct node {
    int value;
    struct node *next;
};

int sum(const int *v, int len)
{
    int total;
    for (int i = 0; i < len; i++)
~>        total += v[i];
    return total;
}

void push(struct node **head, int v)
{
    struct node *n;
~>    n->value = v;
    n->next = *head;
    *head = n;
}

void show(void)
{
    const char *name;
~>    printf("%s\n", name);
}
