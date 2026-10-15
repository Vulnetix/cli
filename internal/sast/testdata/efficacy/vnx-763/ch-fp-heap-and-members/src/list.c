#include <stdlib.h>

struct node {
    char name[32];
    struct node *next;
};

void list_free(struct node *head)
{
    while (head) {
        struct node *next = head->next;
        free(head);
        head = next;
    }
}

void names_free(void)
{
    char *names[8];
    for (int i = 0; i < 8; i++)
        names[i] = malloc(16);
    for (int i = 0; i < 8; i++)
        free(names[i]);
    char *buf = malloc(64);
    free(&buf[0]);
}
