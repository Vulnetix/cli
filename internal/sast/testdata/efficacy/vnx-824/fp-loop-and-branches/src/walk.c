#include <stdio.h>

struct node { int value; struct node *next; };

int sum(struct node *head)
{
    struct node *it;
    int total = 0;
    for (it = head; it; it = it->next)
        total += it->value;
    return total;
}

void label(int ok)
{
    const char *msg;
    if (ok)
        msg = "ok";
    else
        msg = "failed";
    puts(msg);
}
