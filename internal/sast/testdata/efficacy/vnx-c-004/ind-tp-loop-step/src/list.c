#include <stdlib.h>

struct node {
    char *payload;
    struct node *next;
};

void list_destroy(struct node *head)
{
    struct node *it;
~>    for (it = head; it != NULL; it = it->next) {
        free(it->payload);
        free(it);
    }
}
