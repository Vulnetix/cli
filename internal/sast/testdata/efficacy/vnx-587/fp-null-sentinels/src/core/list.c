#include <stddef.h>
#include <sys/mman.h>

#define MAP_FAIL ((void *)-1)
#define LIST_POISON1 ((void *)0x100)
#define INVALID ((void *)0xFFFFFFFF)

void reset(struct node *n)
{
    void *p = (void *)0;
    char *q = (char *)0x0;
    int *r = (int *)NULL;
    void *s = (void *)0x10;
    n->next = (struct node *)0xdeadbeef;
    n->prev = (struct node *)-1;
}
