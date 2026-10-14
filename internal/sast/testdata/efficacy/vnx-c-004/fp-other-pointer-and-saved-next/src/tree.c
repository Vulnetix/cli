#include <stdlib.h>

struct node {
    struct node *next;
    char *name;
};

void free_list(struct node *head)
{
    struct node *cur = head;

    while (cur != NULL) {
        struct node *next = cur->next;
        free(cur->name);
        free(cur);
        cur = next;
    }
}

void free_pair(char *a, char *b, char *pa)
{
    free(a);
    use(b);
    use(pa);
    use(sizeof(a));
}
