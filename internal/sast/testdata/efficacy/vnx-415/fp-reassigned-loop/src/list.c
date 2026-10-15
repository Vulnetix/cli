#include <stdlib.h>

void list_free(struct node *head)
{
    struct node *next;
    while (head) {
        next = head->next;
        free(head);
        head = next;
    }
    free(head);
}

void refill(struct pool *pool)
{
    free(pool->slab);
    pool_alloc(&pool->slab, 4096);
    free(pool->slab);
}

void swap_buf(char *a)
{
    free(a);
    a = realloc(NULL, 10);
    free(a);
}
