#include <stdlib.h>

struct item {
    int value;
    struct item *next;
};

int stack_pop(struct item **head)
{
    struct item *top = *head;
    int v;

    if (top == NULL)
        return -1;
    v = top->value;
    free(top);
~>    *head = top->next;
    return v;
}
