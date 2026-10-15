#include <stdlib.h>

struct node { struct node *next; };

void list_free(struct node *head)
{
    while (head) {
        struct node *next = head->next;
        free(head);
        head = next;
    }
}

void arr_free(char **items, int n)
{
    for (int i = 0; i < n; i++) {
        free(items[i]);
    }
    free(items);
}

void a(char *p)
{
    free(p);
}

void b(char *p)
{
    free(p);
}
