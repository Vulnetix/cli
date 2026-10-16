#include <stdlib.h>

struct node { int value; struct node *next; };

int set_value(int value)
{
    struct node *n;
~>    n->value = value;
    return 0;
}
