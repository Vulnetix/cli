#include <ctype.h>
#include <stddef.h>

struct node { int v; struct node *next; };

char *trim_left(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

struct node **next_slot(struct node *n)
{
    return &n->next;
}

int *element_at(int *arr, size_t i)
{
    return &arr[i];
}

static int counter;

int *global_counter(void)
{
    return &counter;
}
