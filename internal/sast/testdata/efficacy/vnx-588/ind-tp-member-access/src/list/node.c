#include <stddef.h>

struct node {
    struct node *next;
    int value;
};

void reset_counter(void)
{
    unsigned long count;
    count = 0;
~>    ((struct node *) &count)->next = NULL;
}
