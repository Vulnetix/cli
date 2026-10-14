#include <stdlib.h>

struct item {
    struct item *next;
};

void destroy_all(struct item *head)
{
    struct item *it;

~>    for (it = head; it != NULL; it = it->next) {
        free(it);
    }
}

void destroy_brief(struct item *head)
{
    struct item *p;
~>    for (p = head; p; p = p->next)
        free(p);
}

void advance_after_free(struct item *cur)
{
    while (cur) {
        free(cur);
~>        cur = cur->next;
    }
}
