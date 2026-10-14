#include <stdlib.h>

struct node {
    struct node *next;
    int value;
};

int pop_value(struct node **head)
{
    struct node *top = *head;

    free(top);
~>    *head = top->next;
    return 0;
}

void reset_counter(int *counter)
{
    free(counter);
    /* the caller still owns the slot */

~>    *counter = 0;
}

char last_char(char *buf, size_t len)
{
    free(buf);
~>    return buf[len - 1];
}
