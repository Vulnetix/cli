#include <stdlib.h>

struct node {
    int value;
    struct node *next;
};

void push(int value)
{
    struct node *n;
~>    n->value = value;
    n->next = NULL;
}

void sample(void)
{
    double *samples;
~>    samples[0] = 1.0;
}

int total(int x)
{
    int *sum;
~>    *sum += x;
    return x;
}
