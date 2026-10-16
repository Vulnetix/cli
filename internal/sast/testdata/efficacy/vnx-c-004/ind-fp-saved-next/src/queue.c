#include <stdlib.h>

struct msg {
    char *body;
    struct msg *next;
};

void queue_drain(struct msg *head)
{
    struct msg *cur = head;
    while (cur != NULL) {
        struct msg *next = cur->next;
        free(cur->body);
        free(cur);
        cur = next;
    }
}
